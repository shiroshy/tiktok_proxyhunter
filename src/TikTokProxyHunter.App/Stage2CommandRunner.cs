using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Infrastructure;

namespace TikTokProxyHunter.App;

public sealed class Stage2CommandRunner(
    IProxySourceLoader sourceLoader,
    StreamingCandidateProcessor candidateProcessor,
    StreamingProbePipeline probePipeline,
    ISourceHealthEvaluator healthEvaluator,
    ISourceContentFingerprintService fingerprints,
    IGitHubSourceDiscoveryService discovery,
    IExitIpResolver exitIpResolver,
    IExitIpProviderDiagnostics exitIpDiagnostics,
    IProxyGeoResolver geoResolver,
    ILocalGeoIpProvider localGeoProvider,
    IProxyPreScorer preScorer,
    ITikTokCapabilityVerifier capabilityVerifier,
    ITikTokEmbedPlayerVerifier embedPlayerVerifier,
    IProxyStabilityChecker stabilityChecker,
    IBrowserProxyVerifier browserVerifier,
    IAdvancedBrowserProxyVerifier advancedBrowserVerifier,
    IBrowserDoctor browserDoctor,
    IProxyScorer scorer,
    IResultExporter legacyExporter,
    Stage2ResultExporter exporter,
    IRunCheckpointStore checkpointStore,
    HunterOptions hunterOptions,
    GeoOptions geoOptions,
    TikTokVerificationOptions tikTokOptions,
    BrowserVerificationOptions browserOptions,
    PipelineLimits pipelineLimits,
    StabilityOptions stabilityOptions,
    ResultTtlOptions resultTtl,
    TikTokVideoValidationService videoValidation,
    ILogger<Stage2CommandRunner> logger)
{
    public async Task<int> RunAsync(CliOptions cli, CancellationToken cancellationToken) => cli.Command switch
    {
        "refresh-sources" => await RefreshCommandAsync(cli, cancellationToken),
        "discover-sources" => await DiscoverCommandAsync(cli, cancellationToken),
        "import-discovered-sources" => await ImportCommandAsync(cli, cancellationToken),
        "resolve-exit" => await ResolveExitCommandAsync(cli, cancellationToken),
        "resolve-geo" => await ResolveGeoCommandAsync(cli, cancellationToken),
        "verify-tiktok" => await VerifyTikTokCommandAsync(cli, cancellationToken),
        "verify-browser" => await VerifyBrowserCommandAsync(cli, cancellationToken),
        "validate-geo-database" => await ValidateGeoDatabaseCommandAsync(cancellationToken),
        "browser-doctor" => await BrowserDoctorCommandAsync(cancellationToken),
        "verify-browser-live" => await VerifyBrowserLiveCommandAsync(cli, cancellationToken),
        "export-user-list" => await ExportUserListCommandAsync(cli, cancellationToken),
        "explain-proxy" => await ExplainProxyCommandAsync(cli, cancellationToken),
        "test-exit-providers" => await TestExitProvidersCommandAsync(cli, cancellationToken),
        "retry-exit-resolution" => await RetryExitResolutionCommandAsync(cli, cancellationToken),
        "validate-tiktok-videos" => await ValidateTikTokVideosCommandAsync(cli, cancellationToken),
        "continue-verification" => await ContinueVerificationCommandAsync(cli, cancellationToken),
        "all-real" => await AllRealCommandAsync(cli, cancellationToken),
        _ => throw new ArgumentOutOfRangeException(nameof(cli), cli.Command, "Unsupported stage 2 command")
    };

    private async Task<int> RefreshCommandAsync(CliOptions cli, CancellationToken token)
    {
        var context = await RefreshAsync(cli, token);
        await exporter.ExportHealthAsync(cli.OutputPath!, context.Health, token);
        var summary = new RunSummary { Sources = context.Definitions.Count(x => x.Enabled),
            SuccessfulSources = context.SourceResults.Count(x => x.Success), SourceErrors = context.SourceResults.Count(x => !x.Success),
            FoundRows = (int)Math.Min(int.MaxValue, context.Collection.Candidates), ValidCandidates = (int)Math.Min(int.MaxValue, context.Collection.ValidCandidates),
            UniqueEndpoints = context.Collection.Endpoints.Count };
        await legacyExporter.ExportAsync(cli.OutputPath!, [], context.Collection.Endpoints, [], summary, token);
        PrintRefresh(context); return 0;
    }

    private async Task<int> DiscoverCommandAsync(CliOptions cli, CancellationToken token)
    {
        var known = await sourceLoader.LoadDefinitionsAsync(cli.SourcesPath, token);
        var report = await discovery.DiscoverAsync(known, cli.GitHubTokenEnvironment, token);
        await exporter.ExportDiscoveryAsync(cli.OutputPath!, report, token);
        Directory.CreateDirectory("config");
        await File.WriteAllTextAsync(Path.Combine("config", "discovered-proxy-sources.json"),
            JsonSerializer.Serialize(report.Sources, JsonDefaults.Options), token);
        Console.WriteLine($"Repositories/files reviewed: {report.Sources.Count:N0}");
        foreach (var group in report.Sources.GroupBy(x => x.Status)) Console.WriteLine($"{group.Key}: {group.Count():N0}");
        if (report.StopReason is not null) Console.WriteLine($"Stopped safely: {report.StopReason}");
        return 0;
    }

    private async Task<int> ImportCommandAsync(CliOptions cli, CancellationToken token)
    {
        var discoveredPath = Path.Combine("config", "discovered-proxy-sources.json");
        if (!File.Exists(discoveredPath)) throw new FileNotFoundException("Run discover-sources first", discoveredPath);
        var discovered = JsonSerializer.Deserialize<List<DiscoveredProxySource>>(await File.ReadAllTextAsync(discoveredPath, token), JsonDefaults.Options) ?? [];
        var current = (await sourceLoader.LoadDefinitionsAsync(cli.SourcesPath, token)).ToList();
        var existingNames = current.Select(x => x.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var additions = discovered.Where(x => x.Status == SourceDiscoveryStatus.AcceptedForReview && !existingNames.Contains(x.Definition.Name))
            .Select(x => x.Definition with { Enabled = false, Notes = $"Imported for review: {x.Reason}" }).ToArray();
        Console.WriteLine($"Diff: +{additions.Length} disabled source definitions");
        foreach (var item in additions) Console.WriteLine($"+ {item.Name}  {item.Url}");
        if (!cli.Apply) { Console.WriteLine("Dry run only. Re-run with --apply to update the catalog."); return 0; }
        current.AddRange(additions);
        await File.WriteAllTextAsync(cli.SourcesPath, JsonSerializer.Serialize(current, JsonDefaults.Options), token);
        Console.WriteLine($"Applied {additions.Length} additions; all remain disabled for manual review.");
        return 0;
    }

    private async Task<int> ResolveExitCommandAsync(CliOptions cli, CancellationToken token)
    {
        var checks = await RequireInputAsync(cli, token);
        var updated = await ParallelMapAsync(checks, hunterOptions.ProbeConcurrency, async (check, ct) =>
            check.Endpoint.DetectedProtocol is ProxyProtocol.Unknown or ProxyProtocol.Http ? check
                : check with { ExitIp = await exitIpResolver.ResolveAsync(check.Endpoint, ct) }, token);
        await ExportPartialAsync(cli, updated, token); return 0;
    }

    private async Task<int> ResolveGeoCommandAsync(CliOptions cli, CancellationToken token)
    {
        var checks = await RequireInputAsync(cli, token);
        var updated = await ParallelMapAsync(checks, hunterOptions.CollectionConcurrency, async (check, ct) =>
            check.ExitIp?.ExitIp is { } ip ? check with { Geo = await geoResolver.ResolveAsync(ip, ct) } : check, token);
        await ExportPartialAsync(cli, updated, token); return 0;
    }

    private async Task<int> VerifyTikTokCommandAsync(CliOptions cli, CancellationToken token)
    {
        var checks = await RequireInputAsync(cli, token); var videos = ResolveVideoUrls(cli);
        var updated = await ParallelMapAsync(checks, hunterOptions.CollectionConcurrency, async (check, ct) =>
            check with { TikTokCapabilities = await capabilityVerifier.VerifyFastAsync(check.Endpoint, videos, ct) }, token);
        await ExportPartialAsync(cli, updated, token); return 0;
    }

    private async Task<int> VerifyBrowserCommandAsync(CliOptions cli, CancellationToken token)
    {
        var checks = (await RequireInputAsync(cli, token)).Take(cli.BrowserLimit ?? browserOptions.MaximumCandidates).ToArray();
        var video = ResolveVideoUrls(cli).FirstOrDefault();
        if (video is null)
        {
            var notConfigured = checks.Select(x => x with { BrowserVerification = NotConfiguredBrowser(BrowserVerificationMode.OriginalPostPage),
                BrowserPlayback = new() { OriginalPostPlaybackResult = NotConfiguredBrowser(BrowserVerificationMode.OriginalPostPage),
                    EmbedPlayerPlaybackResult = NotConfiguredBrowser(BrowserVerificationMode.OfficialEmbedPlayer) } }).ToArray();
            await ExportPartialAsync(cli, notConfigured, token);
            Console.WriteLine("Browser verification: NotConfigured (no enabled public TikTok test video).");
            return 3;
        }
        var updated = await ParallelMapAsync(checks, browserOptions.Concurrency, async (check, ct) =>
            check with { BrowserVerification = await browserVerifier.VerifyAsync(check.Endpoint, video, ct) }, token);
        await ExportPartialAsync(cli, updated, token); return 0;
    }

    private async Task<int> ValidateGeoDatabaseCommandAsync(CancellationToken token)
    {
        var results = await localGeoProvider.ValidateAsync(token);
        foreach (var result in results)
            Console.WriteLine($"{result.DatabaseType}: exists={result.Exists} format={result.FormatValid} age={result.Age?.TotalDays:0.0}d lookups={result.SuccessfulTestLookups} {result.Reason}");
        return results.All(x => x.Success) ? 0 : 3;
    }

    private async Task<int> BrowserDoctorCommandAsync(CancellationToken token)
    {
        var result = await browserDoctor.DiagnoseAsync(token);
        Console.WriteLine($"Playwright package: {(result.PackageAvailable ? "available" : "missing")}");
        Console.WriteLine($"Chromium: {(result.ChromiumInstalled ? "installed" : "missing")}");
        Console.WriteLine($"Headless launch: {(result.LaunchSucceeded ? "passed" : "not available")}");
        Console.WriteLine($"Clean shutdown: {(result.CleanShutdown ? "passed" : "not verified")}");
        Console.WriteLine($"HTTP proxy config: {result.HttpProxyConfigurationSupported}; SOCKS5 proxy config: {result.Socks5ProxyConfigurationSupported}");
        if (!result.ChromiumInstalled) Console.WriteLine($"Install Chromium: {result.InstallCommand}");
        if (result.Reason is not null) Console.WriteLine($"Reason: {result.Reason}");
        return result.LaunchSucceeded ? 0 : 3;
    }

    private async Task<int> VerifyBrowserLiveCommandAsync(CliOptions cli, CancellationToken token)
    {
        var doctor = await browserDoctor.DiagnoseAsync(token);
        if (!doctor.LaunchSucceeded) throw new InvalidOperationException($"Browser doctor failed. Install command: {doctor.InstallCommand}");
        var videos = ResolveVideoUrls(cli);
        var checks = await RequireInputAsync(cli, token);
        if (videos.Count == 0)
        {
            var notConfigured = checks.Select(x => x with { BrowserPlayback = new()
            { OriginalPostPlaybackResult = NotConfiguredBrowser(BrowserVerificationMode.OriginalPostPage),
              EmbedPlayerPlaybackResult = NotConfiguredBrowser(BrowserVerificationMode.OfficialEmbedPlayer) } }).ToArray();
            await ExportPartialAsync(cli, notConfigured, token);
            Console.WriteLine("Browser live verification: NotConfigured (no enabled public TikTok test video).");
            return 3;
        }
        var candidates = checks.Where(x => Passed(x, TikTokCapability.TikTokHomepage)
                && GeoPolicy.IsBrowserEligible(x.Geo, geoOptions)
                && x.Geo?.Decision is not (GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia))
            .OrderByDescending(x => x.PreScore.Value).ThenByDescending(x => x.Score.Value)
            .ThenBy(x => x.Endpoint.NormalizedKey, StringComparer.OrdinalIgnoreCase)
            .Take(cli.BrowserLimit ?? Math.Min(10, pipelineLimits.MaximumBrowserChecks)).ToArray();
        var updated = await ParallelMapAsync(candidates, Math.Clamp(browserOptions.Concurrency, 1, 2), async (check, ct) =>
        {
            var original = await advancedBrowserVerifier.VerifyAsync(check.Endpoint, videos[0], BrowserVerificationMode.OriginalPostPage, ct);
            var embed = await advancedBrowserVerifier.VerifyAsync(check.Endpoint, videos[0], BrowserVerificationMode.OfficialEmbedPlayer, ct);
            return CapabilityDecisionEngine.Evaluate(check with { BrowserVerification = original, BrowserPlayback = new()
            { OriginalPostPlaybackResult = original, EmbedPlayerPlaybackResult = embed } }, geoOptions, tikTokOptions,
                tikTokOptions.MaximumRecommendedLatencyMs);
        }, token);
        await ExportPartialAsync(cli, updated, token);
        Console.WriteLine($"Original playback verified: {updated.Count(x => x.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.Passed)}/{updated.Length}");
        Console.WriteLine($"Embed playback verified: {updated.Count(x => x.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.Passed)}/{updated.Length}");
        return 0;
    }

    private async Task<int> ExportUserListCommandAsync(CliOptions cli, CancellationToken token)
    {
        var checks = await RequireInputAsync(cli, token);
        await exporter.ExportUserListsAsync(cli.OutputPath!, checks, geoOptions, browserOptions.Enabled, token);
        Console.WriteLine($"User proxy lists written to {Path.GetFullPath(cli.OutputPath!)}");
        return 0;
    }

    private async Task<int> ExplainProxyCommandAsync(CliOptions cli, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(cli.ProxySelector)) throw new ArgumentException("explain-proxy requires --proxy IP:PORT");
        var checks = await RequireInputAsync(cli, token);
        var check = checks.FirstOrDefault(x => $"{x.Endpoint.Host}:{x.Endpoint.Port}".Equals(cli.ProxySelector, StringComparison.OrdinalIgnoreCase)
            || x.Endpoint.NormalizedKey.Equals(cli.ProxySelector, StringComparison.OrdinalIgnoreCase));
        if (check is null) throw new KeyNotFoundException("Proxy endpoint was not found in input");
        Console.WriteLine(ExplainProxyFormatter.Format(check, geoOptions));
        return 0;
    }

    private async Task<int> TestExitProvidersCommandAsync(CliOptions cli, CancellationToken token)
    {
        var attempts = await exitIpDiagnostics.TestDirectAsync(token);
        var health = exitIpDiagnostics.GetHealth();
        Directory.CreateDirectory(cli.OutputPath!);
        await File.WriteAllTextAsync(Path.Combine(cli.OutputPath!, "exit-provider-test.json"),
            JsonSerializer.Serialize(new { attempts, health }, JsonDefaults.Options), token);
        foreach (var attempt in attempts)
            Console.WriteLine($"{attempt.Provider,-20} {attempt.Status,-18} HTTP={attempt.HttpStatus} {attempt.Duration.TotalMilliseconds:0}ms {attempt.Reason}");
        return attempts.Any(x => x.Status == ExitIpStatus.Resolved) ? 0 : 3;
    }

    private async Task<int> RetryExitResolutionCommandAsync(CliOptions cli, CancellationToken token)
    {
        var checks = await RequireInputAsync(cli, token);
        var selected = checks.Where(x => !cli.OnlyTikTokAccessible || HasUsefulTikTokSignal(x)).ToArray();
        var retried = await ParallelMapAsync(selected, Math.Min(32, hunterOptions.ProbeConcurrency), async (check, ct) =>
        {
            var exit = await exitIpResolver.ResolveAsync(check.Endpoint, ct);
            var geo = exit.Status == ExitIpStatus.Resolved && exit.ExitIp is not null ? await geoResolver.ResolveAsync(exit.ExitIp, ct) : check.Geo;
            return CapabilityDecisionEngine.Evaluate(check with { ExitIp = exit, Geo = geo }, geoOptions, tikTokOptions,
                tikTokOptions.MaximumRecommendedLatencyMs);
        }, token);
        await ExportPartialAsync(cli, retried, token);
        Console.WriteLine($"Exit IP resolved after retry: {retried.Count(x => x.ExitIp?.Status == ExitIpStatus.Resolved)}/{retried.Length}");
        return 0;
    }

    private async Task<int> ValidateTikTokVideosCommandAsync(CliOptions cli, CancellationToken token)
    {
        var path = cli.InputPath ?? cli.TikTokVideoFile ?? Path.Combine("config", "tiktok-test-videos.local.json");
        var results = await videoValidation.ValidateAsync(path, token);
        Directory.CreateDirectory(cli.OutputPath!);
        await File.WriteAllTextAsync(Path.Combine(cli.OutputPath!, "tiktok-video-validation.json"),
            JsonSerializer.Serialize(results, JsonDefaults.Options), token);
        foreach (var result in results)
            Console.WriteLine($"{result.Name}: {result.Status}; post={result.PostId ?? "n/a"}; player={result.PlayerHttpStatus}; oEmbed={result.OEmbedHttpStatus}; {result.Reason}");
        return results.Any(x => x.Suitable) ? 0 : results.All(x => x.Status == TikTokCapabilityStatus.NotConfigured) ? 3 : 4;
    }

    private async Task<int> ContinueVerificationCommandAsync(CliOptions cli, CancellationToken token)
    {
        var checks = await RequireInputAsync(cli, token); var videos = ResolveVideoUrls(cli);
        var now = DateTimeOffset.UtcNow;
        var protocolFresh = checks.Where(x => ResultFreshness.ProtocolFresh(x.Probe, resultTtl, now)).ToArray();
        var staleEndpoints = checks.Where(x => !ResultFreshness.ProtocolFresh(x.Probe, resultTtl, now)).Select(x => x.Endpoint).ToArray();
        var reprobed = staleEndpoints.Length == 0 ? [] : await probePipeline.ProbeAsync(staleEndpoints, null, token);
        var input = protocolFresh.Concat(reprobed).ToArray();
        var continued = await ParallelMapAsync(input, hunterOptions.CollectionConcurrency, async (check, ct) =>
            await ContinueOneAsync(check, videos, ct), token);
        var final = continued.Select(x => CapabilityDecisionEngine.Evaluate(x with { Score = scorer.Calculate(x) }, geoOptions, tikTokOptions,
                tikTokOptions.MaximumRecommendedLatencyMs))
            .OrderByDescending(x => x.Score.Value).ThenBy(x => x.Endpoint.NormalizedKey).ToArray();
        await ExportPartialAsync(cli, final, token);
        await exporter.ExportCapabilityMatrixAsync(cli.OutputPath!, CapabilityMatrixBuilder.Build(final), token);
        return 0;
    }

    private async Task<ProxyCheckResult> ContinueOneAsync(ProxyCheckResult check, IReadOnlyList<Uri> videos, CancellationToken token)
    {
        var now = DateTimeOffset.UtcNow; var value = check;
        var homepage = value.TikTokCapabilities.LastOrDefault(x => x.Capability == TikTokCapability.TikTokHomepage);
        if (!ResultFreshness.CapabilityFresh(homepage, resultTtl, now))
            value = AddCapabilities(value, await capabilityVerifier.VerifyCapabilityAsync(value.Endpoint, TikTokCapability.TikTokHomepage, null, token));
        if (!ResultFreshness.ExitFresh(value.ExitIp, resultTtl, now)) value = value with { ExitIp = await exitIpResolver.ResolveAsync(value.Endpoint, token) };
        if (value.ExitIp?.Status == ExitIpStatus.Resolved && value.ExitIp.ExitIp is { } ip && !ResultFreshness.GeoFresh(value.Geo, resultTtl, now))
            value = value with { Geo = await geoResolver.ResolveAsync(ip, token) };
        if (HasUsefulTikTokSignal(value) && !ResultFreshness.StabilityFresh(value.TikTokPageStability ?? value.Stability, resultTtl, now))
        {
            var capability = SelectStabilityCapability(value);
            value = value with { TikTokPageStability = await stabilityChecker.CheckAsync(value.Endpoint, capability, videos.FirstOrDefault(), token) };
        }
        if (videos.Count > 0 && !Passed(value, TikTokCapability.TikTokEmbedPlayer))
            value = await VerifyVideoCapabilitiesAsync(value, videos[0], token);
        if (videos.Count > 0 && browserOptions.Enabled && HasUsefulTikTokSignal(value)
            && (!ResultFreshness.BrowserFresh(value.BrowserPlayback.OriginalPostPlaybackResult, resultTtl, now)
                || !ResultFreshness.BrowserFresh(value.BrowserPlayback.EmbedPlayerPlaybackResult, resultTtl, now)))
        {
            var original = ResultFreshness.BrowserFresh(value.BrowserPlayback.OriginalPostPlaybackResult, resultTtl, now)
                ? value.BrowserPlayback.OriginalPostPlaybackResult!
                : await advancedBrowserVerifier.VerifyAsync(value.Endpoint, videos[0], BrowserVerificationMode.OriginalPostPage, token);
            var embed = ResultFreshness.BrowserFresh(value.BrowserPlayback.EmbedPlayerPlaybackResult, resultTtl, now)
                ? value.BrowserPlayback.EmbedPlayerPlaybackResult!
                : await advancedBrowserVerifier.VerifyAsync(value.Endpoint, videos[0], BrowserVerificationMode.OfficialEmbedPlayer, token);
            value = value with { BrowserVerification = original, BrowserPlayback = new()
            { OriginalPostPlaybackResult = original, EmbedPlayerPlaybackResult = embed } };
        }
        return value;
    }

    private async Task<int> AllRealCommandAsync(CliOptions cli, CancellationToken token)
    {
        var funnel = new List<PipelineStageStatistics>();
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var context = await RefreshAsync(cli, token); PrintRefresh(context);
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.Collected, context.Collection.Candidates,
            context.Collection.Candidates, watch.Elapsed));
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.Normalized, context.Collection.Candidates,
            context.Collection.Endpoints.Count, watch.Elapsed,
            Enumerable.Repeat("invalid/private/duplicate/limit", (int)Math.Max(0, context.Collection.Candidates - context.Collection.Endpoints.Count))));

        var sourceConfig = await File.ReadAllTextAsync(cli.SourcesPath, token);
        var videos = ResolveVideoUrls(cli);
        var configurationHash = RunCheckpointStore.ComputeConfigurationHash(sourceConfig,
            JsonSerializer.Serialize(hunterOptions, JsonDefaults.CompactOptions), JsonSerializer.Serialize(geoOptions, JsonDefaults.CompactOptions),
            JsonSerializer.Serialize(pipelineLimits, JsonDefaults.CompactOptions), string.Join('|', videos.Select(x => x.AbsoluteUri)), cli.BrowserCheck.ToString());
        var checkpointPath = Path.Combine(cli.OutputPath!, "run-checkpoint.json");
        var statePath = Path.Combine(cli.OutputPath!, "run-state.private.json");
        var checkpoint = cli.Resume ? await checkpointStore.LoadAsync(checkpointPath, token) : null;
        var canResume = RunCheckpointStore.CanResume(checkpoint, configurationHash) && File.Exists(statePath);
        if (cli.Resume && checkpoint is not null && !canResume) logger.LogWarning("Checkpoint cannot be resumed because configuration changed or state is missing");
        var existing = canResume
            ? JsonSerializer.Deserialize<List<ProxyCheckResult>>(await File.ReadAllTextAsync(statePath, token), JsonDefaults.Options) ?? [] : [];

        var protocolInput = context.Collection.Endpoints
            .OrderByDescending(x => x.SourceFamilies.Distinct(StringComparer.OrdinalIgnoreCase).Count())
            .ThenByDescending(x => x.RetrievedAt).ThenBy(x => x.NormalizedKey, StringComparer.OrdinalIgnoreCase)
            .Take(pipelineLimits.MaximumProtocolChecks <= 0 ? int.MaxValue : pipelineLimits.MaximumProtocolChecks).ToArray();
        watch.Restart();
        var completedProbe = canResume ? existing.Select(x => x.Endpoint.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase) : null;
        var probed = await probePipeline.ProbeAsync(protocolInput, completedProbe, token);
        var checks = existing.Concat(probed).GroupBy(x => x.Endpoint.NormalizedKey).Select(x => x.Last()).ToArray();
        checks = checks.Select(x => x with { PreScore = preScorer.Calculate(x) }).ToArray();
        var alive = checks.Where(x => x.Probe?.Success == true).ToArray();
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.ProtocolAlive, protocolInput.Length, alive.Length, watch.Elapsed,
            checks.Where(x => x.Probe?.Success != true).Select(x => x.Probe?.FailureReason ?? "protocol handshake failed"),
            checks.Select(x => (x.Probe?.ConnectTime + x.Probe?.TunnelTime)?.TotalMilliseconds ?? 0)));

        var all = new Dictionary<string, ProxyCheckResult>(checks.ToDictionary(x => x.Endpoint.NormalizedKey), StringComparer.OrdinalIgnoreCase);
        var tunnelAlive = alive.Where(x => x.Endpoint.DetectedProtocol != ProxyProtocol.Http).ToArray();
        var fastInput = DeterministicPipelineLimiter.Take(tunnelAlive, pipelineLimits.MaximumFastTikTokChecks);
        watch.Restart();
        var fast = await ParallelMapAsync(fastInput, Math.Min(32, hunterOptions.ProbeConcurrency), async (check, ct) =>
        {
            var shortHttps = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.ShortGenericHttps, null, ct);
            var homepageResult = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.TikTokHomepage, null, ct);
            var mobileResult = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.TikTokMobilePage, null, ct);
            return check with { TikTokCapabilities = [shortHttps, homepageResult, mobileResult] };
        }, token);
        Merge(all, fast);
        var shortPassed = fast.Where(x => Passed(x, TikTokCapability.ShortGenericHttps)).ToArray();
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.ShortHttpsPassed, fast.Length, shortPassed.Length, watch.Elapsed,
            fast.Where(x => !Passed(x, TikTokCapability.ShortGenericHttps)).Select(x => CapabilityFailure(x, TikTokCapability.ShortGenericHttps))));
        var homepage = fast.Where(x => Passed(x, TikTokCapability.TikTokHomepage)).ToArray();
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.TikTokHomepagePassed, fast.Length, homepage.Length, watch.Elapsed,
            fast.Where(x => !Passed(x, TikTokCapability.TikTokHomepage)).Select(x => CapabilityFailure(x, TikTokCapability.TikTokHomepage)),
            fast.SelectMany(x => x.TikTokCapabilities.Where(c => c.Capability == TikTokCapability.TikTokHomepage).Select(c => c.Duration.TotalMilliseconds))));
        var mobile = fast.Where(x => Passed(x, TikTokCapability.TikTokMobilePage)).ToArray();
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.TikTokMobilePassed, fast.Length, mobile.Length, TimeSpan.Zero,
            fast.Where(x => !Passed(x, TikTokCapability.TikTokMobilePage)).Select(x => CapabilityFailure(x, TikTokCapability.TikTokMobilePage))));
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.FastTikTokEligible, tunnelAlive.Length, fast.Length, TimeSpan.Zero,
            tunnelAlive.Except(fastInput).Select(_ => "LimitReached")));

        var exitInput = DeterministicPipelineLimiter.Take(tunnelAlive, pipelineLimits.MaximumExitIpChecks);
        watch.Restart();
        var exited = await ParallelMapAsync(exitInput, Math.Min(32, hunterOptions.ProbeConcurrency), async (baseCheck, ct) =>
        {
            var current = all[baseCheck.Endpoint.NormalizedKey];
            var value = current with { ExitIp = await exitIpResolver.ResolveAsync(current.Endpoint, ct) };
            return value with { PreScore = preScorer.Calculate(value) };
        }, token);
        Merge(all, exited);
        var resolved = exited.Where(x => x.ExitIp?.Status == ExitIpStatus.Resolved).ToArray();
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.ExitIpResolved, exitInput.Count, resolved.Length, watch.Elapsed,
            exited.Where(x => x.ExitIp?.Status != ExitIpStatus.Resolved).Select(x => x.ExitIp?.Status.ToString() ?? "not resolved"),
            exited.SelectMany(x => x.ExitIp?.Attempts.Select(p => p.Duration.TotalMilliseconds) ?? [])));

        watch.Restart();
        var geoEvaluated = await ParallelMapAsync(resolved, Math.Min(16, hunterOptions.CollectionConcurrency * 2), async (check, ct) =>
        {
            var value = check with { Geo = await geoResolver.ResolveAsync(check.ExitIp!.ExitIp!, ct) };
            return value with { PreScore = preScorer.Calculate(value) };
        }, token);
        Merge(all, geoEvaluated);
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.GeoEvaluated, resolved.Length, geoEvaluated.Length, watch.Elapsed));

        var stabilityInput = DeterministicPipelineLimiter.Take(all.Values.Where(HasUsefulTikTokSignal), pipelineLimits.MaximumStabilityChecks);
        watch.Restart();
        var stability = await ParallelMapAsync(stabilityInput, Math.Min(10, hunterOptions.CollectionConcurrency), async (check, ct) =>
        {
            var capability = SelectStabilityCapability(check);
            var result = await stabilityChecker.CheckAsync(check.Endpoint, capability, videos.FirstOrDefault(), ct);
            return check with { Stability = result, TikTokPageStability = result };
        }, token);
        Merge(all, stability);
        var stable = stability.Where(x => x.TikTokPageStability?.Status == ProxyStabilityStatus.Stable).ToArray();
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.StabilityPassed, stabilityInput.Count, stable.Length, watch.Elapsed,
            stability.Where(x => x.TikTokPageStability?.Status != ProxyStabilityStatus.Stable).Select(x => x.TikTokPageStability?.Status.ToString() ?? "NotEligible"),
            stability.Select(x => x.TikTokPageStability?.MedianLatencyMs ?? 0)));

        var videoCandidates = DeterministicPipelineLimiter.Take(all.Values.Where(x => HasUsefulTikTokSignal(x)
            || Passed(x, TikTokCapability.ShortGenericHttps)), pipelineLimits.MaximumVideoPageChecks);
        watch.Restart();
        ProxyCheckResult[] videoResults;
        if (videos.Count == 0)
        {
            videoResults = videoCandidates.Select(x => AddCapabilities(x,
                NotConfigured(TikTokCapability.TikTokPostPage), NotConfigured(TikTokCapability.TikTokOEmbed),
                NotConfigured(TikTokCapability.TikTokEmbedPlayer))).ToArray();
        }
        else
        {
            videoResults = await ParallelMapAsync(videoCandidates, hunterOptions.CollectionConcurrency,
                async (check, ct) => await VerifyVideoCapabilitiesAsync(check, videos[0], ct), token);
        }
        Merge(all, videoResults);
        var videoPassed = videoResults.Where(x => Passed(x, TikTokCapability.TikTokPostPage)).ToArray();
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.PublicVideoPassed, videoCandidates.Count, videoPassed.Length, watch.Elapsed,
            videoResults.Where(x => !Passed(x, TikTokCapability.TikTokPostPage)).Select(x => CapabilityFailure(x, TikTokCapability.TikTokPostPage))));

        // A post/player success is also independently eligible for stability even when homepage/mobile failed.
        var laterStabilityInput = DeterministicPipelineLimiter.Take(videoResults.Where(x => HasUsefulTikTokSignal(x)
            && (x.TikTokPageStability ?? x.Stability) is null), Math.Max(0, pipelineLimits.MaximumStabilityChecks - stabilityInput.Count));
        var laterStability = await ParallelMapAsync(laterStabilityInput, Math.Min(10, hunterOptions.CollectionConcurrency), async (check, ct) =>
        {
            var capability = SelectStabilityCapability(check);
            var result = await stabilityChecker.CheckAsync(check.Endpoint, capability, videos.FirstOrDefault(), ct);
            return check with { Stability = result, TikTokPageStability = result };
        }, token);
        Merge(all, laterStability);

        var browserEnabled = cli.BrowserCheck || browserOptions.Enabled;
        var browserMaximum = Math.Min(cli.BrowserLimit ?? pipelineLimits.MaximumBrowserChecks, pipelineLimits.MaximumBrowserChecks);
        var browserInput = browserEnabled && videos.Count > 0
            ? DeterministicPipelineLimiter.Take(videoResults.Where(x => HasUsefulTikTokSignal(x)
                && x.Geo?.Decision is not (GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia)), browserMaximum) : [];
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.BrowserEligible, videoResults.Length, browserInput.Count, TimeSpan.Zero,
            browserEnabled && videos.Count > 0 ? videoResults.Except(browserInput).Select(_ => "NotEligibleOrLimitReached")
                : videoResults.Select(_ => videos.Count == 0 ? "NotConfigured" : "BrowserUnavailable")));
        watch.Restart();
        var browserResults = await ParallelMapAsync(browserInput, Math.Clamp(browserOptions.Concurrency, 1, 2), async (check, ct) =>
        {
            var original = await advancedBrowserVerifier.VerifyAsync(check.Endpoint, videos[0], BrowserVerificationMode.OriginalPostPage, ct);
            var embed = await advancedBrowserVerifier.VerifyAsync(check.Endpoint, videos[0], BrowserVerificationMode.OfficialEmbedPlayer, ct);
            var playbackStability = original.Status == BrowserVerificationStatus.Passed
                ? await CheckBrowserStabilityAsync(check.Endpoint, videos[0], BrowserVerificationMode.OriginalPostPage, original, ct)
                : embed.Status == BrowserVerificationStatus.Passed
                    ? await CheckBrowserStabilityAsync(check.Endpoint, videos[0], BrowserVerificationMode.OfficialEmbedPlayer, embed, ct) : null;
            return check with { BrowserVerification = original, BrowserPlayback = new()
            { OriginalPostPlaybackResult = original, EmbedPlayerPlaybackResult = embed }, PlaybackStability = playbackStability };
        }, token);
        Merge(all, browserResults);
        var playback = browserResults.Where(x => x.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.Passed
            || x.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.Passed).ToArray();
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.PlaybackVerified, browserInput.Count, playback.Length, watch.Elapsed,
            browserResults.Where(x => !playback.Contains(x)).Select(x => x.BrowserPlayback.EmbedPlayerPlaybackResult?.Status.ToString() ?? "NotConfigured")));

        var final = all.Values.Select(x =>
        {
            var prescored = x with { PreScore = preScorer.Calculate(x) };
            var scored = prescored with { Score = scorer.Calculate(prescored) };
            return CapabilityDecisionEngine.Evaluate(scored, geoOptions, tikTokOptions, tikTokOptions.MaximumRecommendedLatencyMs);
        }).OrderByDescending(x => x.Score.Value).ThenBy(x => x.Endpoint.NormalizedKey).ToArray();
        var recommended = final.Count(x => x.RecommendationClass == ProxyRecommendationClass.Recommended);
        funnel.Add(PipelineFunnelBuilder.Create(PipelineStage.Recommended, final.Length, recommended, TimeSpan.Zero,
            final.Where(x => x.RecommendationClass != ProxyRecommendationClass.Recommended).Select(x => ExplainProxyFormatter.NotRecommendedReasons(x, geoOptions).FirstOrDefault() ?? "criteria not met")));

        var finalCheckpoint = new RunCheckpoint { ConfigurationHash = configurationHash, Stage = "complete",
            CompletedEndpointKeys = final.Select(x => x.Endpoint.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase),
            ProbedEndpointKeys = checks.Select(x => x.Endpoint.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase) };
        await File.WriteAllTextAsync(statePath, JsonSerializer.Serialize(final, JsonDefaults.Options), token);
        logger.LogWarning("Resume state can contain proxy credentials. Protect access to {Path}", statePath);
        await exporter.ExportStage2Async(cli.OutputPath!, final, context.Health, finalCheckpoint, token);
        await exporter.ExportFunnelAsync(cli.OutputPath!, new PipelineFunnel { Stages = funnel }, token);
        await exporter.ExportCapabilityMatrixAsync(cli.OutputPath!, CapabilityMatrixBuilder.Build(final), token);
        await exporter.ExportUserListsAsync(Path.Combine(cli.OutputPath!, "user-proxies"), final, geoOptions, browserEnabled, token);
        await checkpointStore.SaveAsync(checkpointPath, finalCheckpoint, token);
        PrintAllReal(final); return 0;
    }

    private async Task<RefreshContext> RefreshAsync(CliOptions cli, CancellationToken token)
    {
        var all = await sourceLoader.LoadDefinitionsAsync(cli.SourcesPath, token);
        var selected = all.Where(x => cli.IncludeSources.Count == 0 || cli.IncludeSources.Any(v => x.Name.Contains(v, StringComparison.OrdinalIgnoreCase)))
            .Where(x => !cli.ExcludeSources.Any(v => x.Name.Contains(v, StringComparison.OrdinalIgnoreCase))).ToArray();
        var results = await sourceLoader.LoadEnabledAsync(selected, token);
        var byName = selected.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
        var collection = await candidateProcessor.ProcessAsync(results.Where(x => byName.ContainsKey(x.SourceName))
            .Select(x => (byName[x.SourceName], x)), token);
        var preliminary = new List<ProxySourceHealth>();
        foreach (var definition in selected)
        {
            if (!definition.Enabled) { preliminary.Add(healthEvaluator.Evaluate(definition, new ProxySourceResult { SourceName = definition.Name }, 0, 0, 0)); continue; }
            var result = results.FirstOrDefault(x => x.SourceName.Equals(definition.Name, StringComparison.OrdinalIgnoreCase))
                ?? new ProxySourceResult { SourceName = definition.Name, Error = "No source result" };
            collection.SourceCounts.TryGetValue(definition.Name, out var counts);
            preliminary.Add(healthEvaluator.Evaluate(definition, result, counts.Extracted, counts.Valid, result.Success ? 0 : result.Attempts));
        }
        var mirrors = fingerprints.FindExactMirrors(preliminary);
        var health = preliminary.Select(x => mirrors.TryGetValue(x.SourceName, out var duplicate)
            ? x with { DuplicateOf = duplicate, Status = ProxySourceHealthStatus.Degraded } : x).ToArray();
        return new RefreshContext(selected, results, collection, health);
    }

    private async Task ExportPartialAsync(CliOptions cli, IReadOnlyList<ProxyCheckResult> results, CancellationToken token)
    {
        var hash = RunCheckpointStore.ComputeConfigurationHash(cli.Command, JsonSerializer.Serialize(hunterOptions, JsonDefaults.CompactOptions));
        var checkpoint = new RunCheckpoint { ConfigurationHash = hash, Stage = cli.Command,
            CompletedEndpointKeys = results.Select(x => x.Endpoint.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase) };
        await exporter.ExportStage2Async(cli.OutputPath!, results, [], checkpoint, token);
        Console.WriteLine($"Processed: {results.Count:N0}; output: {Path.GetFullPath(cli.OutputPath!)}");
    }

    private static async Task<IReadOnlyList<ProxyCheckResult>> RequireInputAsync(CliOptions cli, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(cli.InputPath)) throw new ArgumentException($"Command '{cli.Command}' requires --input");
        return await Stage2InputReader.ReadAsync(cli.InputPath, token);
    }

    private IReadOnlyList<Uri> ResolveVideoUrls(CliOptions cli)
    {
        var values = cli.TikTokVideoUrls.Concat(tikTokOptions.PublicVideoTestUrls).ToList();
        var localPath = cli.TikTokVideoFile ?? Path.Combine("config", "tiktok-test-videos.local.json");
        values.AddRange(TikTokVideoConfigLoader.Load(localPath).Where(x => x.Enabled).Select(x => x.Url));
        var result = new List<Uri>();
        foreach (var value in values)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
                throw new ArgumentException("Invalid TikTok video URL (not an absolute URI). Full query is not logged.");
            if (!TikTokVideoUrlParser.TryParse(uri, tikTokOptions.AllowedVideoDomains, out _, out _, out var reason))
                throw new ArgumentException($"Invalid TikTok video URL ({reason}). Full query is not logged.");
            result.Add(TikTokVideoUrlParser.Sanitize(uri));
        }
        return result.DistinctBy(x => x.AbsoluteUri).ToArray();
    }

    private static void Merge(Dictionary<string, ProxyCheckResult> destination, IEnumerable<ProxyCheckResult> values)
    { foreach (var value in values) destination[value.Endpoint.NormalizedKey] = value; }
    private static bool Passed(ProxyCheckResult result, TikTokCapability capability) =>
        result.TikTokCapabilities.Any(x => x.Capability == capability && x.Status == TikTokCapabilityStatus.Passed);
    private static string CapabilityFailure(ProxyCheckResult result, TikTokCapability capability) =>
        result.TikTokCapabilities.FirstOrDefault(x => x.Capability == capability)?.Status.ToString() ?? "not run";

    private static bool HasUsefulTikTokSignal(ProxyCheckResult result) =>
        Passed(result, TikTokCapability.TikTokHomepage) || Passed(result, TikTokCapability.TikTokPostPage)
        || Passed(result, TikTokCapability.TikTokEmbedPlayer)
        || result.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.Passed
        || result.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.Passed;

    private static TikTokCapability SelectStabilityCapability(ProxyCheckResult result) =>
        Passed(result, TikTokCapability.TikTokHomepage) ? TikTokCapability.TikTokHomepage
        : Passed(result, TikTokCapability.TikTokPostPage) ? TikTokCapability.TikTokPostPage
        : TikTokCapability.TikTokEmbedPlayer;

    private async Task<ProxyCheckResult> VerifyVideoCapabilitiesAsync(ProxyCheckResult check, Uri video, CancellationToken token)
    {
        var post = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.TikTokPostPage, video, token);
        var oembed = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.TikTokOEmbed, video, token);
        var embedResult = await embedPlayerVerifier.VerifyAsync(check.Endpoint, video, token);
        var embed = new TikTokCapabilityResult { Capability = TikTokCapability.TikTokEmbedPlayer,
            Status = embedResult.Status, Url = embedResult.RequestedUrl, Duration = embedResult.Latency,
            HttpStatus = embedResult.HttpStatus, Reason = embedResult.FailureReason };
        var value = AddCapabilities(check, post, oembed, embed);
        return value with { EmbedPlayerResults = value.EmbedPlayerResults
            .Where(x => !x.PostId.Equals(embedResult.PostId, StringComparison.Ordinal)).Append(embedResult).ToArray() };
    }

    private static ProxyCheckResult AddCapabilities(ProxyCheckResult check, params TikTokCapabilityResult[] additions)
    {
        var replaced = additions.Select(x => x.Capability).ToHashSet();
        return check with { TikTokCapabilities = check.TikTokCapabilities.Where(x => !replaced.Contains(x.Capability)).Concat(additions).ToArray() };
    }

    private static TikTokCapabilityResult NotConfigured(TikTokCapability capability) => new()
    { Capability = capability, Status = TikTokCapabilityStatus.NotConfigured,
      Reason = $"{CapabilityNotRunReason.NotConfigured}: no enabled public TikTok test video" };

    private static BrowserVerificationResult NotConfiguredBrowser(BrowserVerificationMode mode) => new()
    { Mode = mode, Status = BrowserVerificationStatus.NotConfigured,
      Reason = $"{CapabilityNotRunReason.NotConfigured}: no enabled public TikTok test video" };

    private async Task<ProxyStabilityResult> CheckBrowserStabilityAsync(ProxyEndpoint endpoint, Uri video,
        BrowserVerificationMode mode, BrowserVerificationResult first, CancellationToken token)
    {
        var attempts = new List<ProxyCheckAttempt>
        {
            new() { Attempt = 1, Success = first.Status == BrowserVerificationStatus.Passed,
                Latency = first.Elapsed, Status = first.Status == BrowserVerificationStatus.Passed
                    ? TikTokCapabilityStatus.Passed : TikTokCapabilityStatus.Failed, Error = first.Reason }
        };
        for (var attempt = 2; attempt <= stabilityOptions.Attempts; attempt++)
        {
            if (stabilityOptions.DelaySeconds > 0) await Task.Delay(TimeSpan.FromSeconds(stabilityOptions.DelaySeconds), token);
            var result = await advancedBrowserVerifier.VerifyAsync(endpoint, video, mode, token);
            attempts.Add(new() { Attempt = attempt, Success = result.Status == BrowserVerificationStatus.Passed,
                Latency = result.Elapsed, Status = result.Status == BrowserVerificationStatus.Passed
                    ? TikTokCapabilityStatus.Passed : result.Status == BrowserVerificationStatus.Timeout
                        ? TikTokCapabilityStatus.Timeout : TikTokCapabilityStatus.Failed, Error = result.Reason });
        }
        return StabilityCalculator.Calculate(attempts, stabilityOptions) with
        { Capability = mode == BrowserVerificationMode.OfficialEmbedPlayer
            ? TikTokCapability.TikTokEmbedPlayerPlayback : TikTokCapability.TikTokOriginalPostPlayback };
    }

    private static async Task<T[]> ParallelMapAsync<T>(IReadOnlyList<T> input, int concurrency,
        Func<T, CancellationToken, Task<T>> action, CancellationToken token)
    {
        var results = new ConcurrentBag<T>();
        await Parallel.ForEachAsync(input, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, concurrency), CancellationToken = token },
            async (item, ct) => results.Add(await action(item, ct)));
        return results.ToArray();
    }

    private static void PrintRefresh(RefreshContext context)
    {
        Console.WriteLine($"Sources healthy/degraded: {context.Health.Count(x => x.Status == ProxySourceHealthStatus.Healthy)}/{context.Health.Count(x => x.Status == ProxySourceHealthStatus.Degraded)}; failures: {context.Health.Count(x => x.Status is not (ProxySourceHealthStatus.Healthy or ProxySourceHealthStatus.Degraded or ProxySourceHealthStatus.Disabled))}");
        Console.WriteLine($"Candidates: {context.Collection.Candidates:N0}; valid: {context.Collection.ValidCandidates:N0}; unique: {context.Collection.Endpoints.Count:N0}; memory-limit drops: {context.Collection.DroppedByMemoryLimit:N0}");
    }

    private static void PrintAllReal(IReadOnlyList<ProxyCheckResult> results)
    {
        Console.WriteLine($"Exit IP resolved: {results.Count(x => x.ExitIp?.Status == ExitIpStatus.Resolved):N0}");
        Console.WriteLine($"RU exits rejected: {results.Count(x => x.Geo?.Decision is GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia):N0}");
        foreach (var capability in Enum.GetValues<TikTokCapability>())
            Console.WriteLine($"{capability}: {results.Count(x => x.TikTokCapabilities.Any(c => c.Capability == capability && c.Status == TikTokCapabilityStatus.Passed)):N0}");
        Console.WriteLine($"PlaybackVerified: {results.Count(x => x.BrowserVerification?.Status == BrowserVerificationStatus.Passed):N0}");
        Console.WriteLine($"Recommended: {results.Count(x => x.RecommendationClass == ProxyRecommendationClass.Recommended):N0}");
    }

    private sealed record RefreshContext(IReadOnlyList<ProxySourceDefinition> Definitions,
        IReadOnlyList<ProxySourceResult> SourceResults, StreamingCollectionResult Collection, IReadOnlyList<ProxySourceHealth> Health);
}

internal static class Stage2InputReader
{
    public static async Task<IReadOnlyList<ProxyCheckResult>> ReadAsync(string path, CancellationToken token)
    {
        var text = await File.ReadAllTextAsync(path, token); var records = new List<ProxyCheckResult>();
        if (Path.GetExtension(path).Equals(".jsonl", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            { using var document = JsonDocument.Parse(line); Add(document.RootElement, records); }
        }
        else
        {
            using var document = JsonDocument.Parse(text);
            if (document.RootElement.ValueKind == JsonValueKind.Array) foreach (var element in document.RootElement.EnumerateArray()) Add(element, records);
            else Add(document.RootElement, records);
        }
        return records;
    }

    private static void Add(JsonElement element, List<ProxyCheckResult> records)
    {
        if (element.ValueKind != JsonValueKind.Object) return;
        if (element.TryGetProperty("host", out _))
        {
            var endpoint = element.Deserialize<ProxyEndpoint>(JsonDefaults.Options); if (endpoint is not null) records.Add(new ProxyCheckResult { Endpoint = endpoint }); return;
        }
        if (!element.TryGetProperty("endpoint", out var endpointElement)) return;
        if (element.TryGetProperty("probe", out _) && !element.TryGetProperty("detectedProtocol", out _))
        {
            var check = element.Deserialize<ProxyCheckResult>(JsonDefaults.Options); if (check is not null) records.Add(check); return;
        }
        var endpointValue = endpointElement.Deserialize<ProxyEndpoint>(JsonDefaults.Options); if (endpointValue is null) return;
        if (element.TryGetProperty("detectedProtocol", out _))
        {
            records.Add(new ProxyCheckResult
            {
                Endpoint = endpointValue,
                Probe = Deserialize<ProxyProbeResult>(element, "probe"),
                ExitIp = Deserialize<ExitIpResolutionResult>(element, "exitIpResolution"),
                Geo = Deserialize<ProxyGeoInfo>(element, "geo"),
                PreScore = Deserialize<ProxyPreScore>(element, "preScore") ?? new(0, false, []),
                Stability = Deserialize<ProxyStabilityResult>(element, "stability"),
                NetworkStability = Deserialize<ProxyStabilityResult>(element, "networkStability"),
                TikTokPageStability = Deserialize<ProxyStabilityResult>(element, "tikTokPageStability"),
                PlaybackStability = Deserialize<ProxyStabilityResult>(element, "playbackStability"),
                TikTokChecks = Deserialize<IReadOnlyList<TikTokCheckResult>>(element, "tikTokChecks") ?? [],
                TikTokCapabilities = Deserialize<IReadOnlyList<TikTokCapabilityResult>>(element, "tikTokCapabilities") ?? [],
                BrowserVerification = Deserialize<BrowserVerificationResult>(element, "browserPlayback"),
                BrowserPlayback = Deserialize<BrowserPlaybackSet>(element, "browserPlaybackSet") ?? new(),
                EmbedPlayerResults = Deserialize<IReadOnlyList<TikTokEmbedPlayerResult>>(element, "embedPlayerResults") ?? [],
                TechnicalAccess = DeserializeEnum(element, "technicalAccess", TechnicalTikTokAccess.None),
                PlaybackCapability = DeserializeEnum(element, "playbackCapability", PlaybackCapability.None),
                RecommendationEligibility = DeserializeEnum(element, "recommendationEligibility", RecommendationEligibility.NoTechnicalAccess),
                Score = Deserialize<ProxyScore>(element, "score") ?? new(0, []),
                RecommendationClass = element.TryGetProperty("recommendationClass", out var recommendation)
                    && Enum.TryParse<ProxyRecommendationClass>(recommendation.ToString(), true, out var parsed) ? parsed : ProxyRecommendationClass.Rejected,
                SuccessfulChecks = element.TryGetProperty("successfulChecks", out var successes) ? successes.GetInt32() : 0
            });
            return;
        }
        var record = new ProxyCheckResult { Endpoint = endpointValue };
        if (element.TryGetProperty("result", out var result))
        {
            if (result.TryGetProperty("providers", out _)) record = record with { ExitIp = result.Deserialize<ExitIpResolutionResult>(JsonDefaults.Options) };
            else if (result.TryGetProperty("countryCode", out _)) record = record with { Geo = result.Deserialize<ProxyGeoInfo>(JsonDefaults.Options) };
        }
        records.Add(record);
    }

    private static T? Deserialize<T>(JsonElement element, string property) where T : class =>
        element.TryGetProperty(property, out var value) && value.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined)
            ? value.Deserialize<T>(JsonDefaults.Options) : null;

    private static T DeserializeEnum<T>(JsonElement element, string property, T fallback) where T : struct, Enum =>
        element.TryGetProperty(property, out var value) && Enum.TryParse<T>(value.ToString(), true, out var parsed) ? parsed : fallback;
}
