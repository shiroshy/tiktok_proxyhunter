using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public sealed class HunterProgressSink(IHunterRunObserver observer, TimeSpan? minimumInterval = null) : IHunterProgressSink
{
    private readonly TimeSpan _minimumInterval = minimumInterval ?? TimeSpan.FromMilliseconds(125);
    private readonly object _gate = new();
    private DateTimeOffset _lastStageProgress = DateTimeOffset.MinValue;

    public ValueTask PublishAsync(HunterRunProgress progress, CancellationToken cancellationToken)
    {
        if (progress.Event != HunterProgressEvent.StageProgress) return observer.OnProgressAsync(progress, cancellationToken);
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (now - _lastStageProgress < _minimumInterval) return ValueTask.CompletedTask;
            _lastStageProgress = now;
        }
        return observer.OnProgressAsync(progress, cancellationToken);
    }
}

public sealed class HunterRunController(IHunterRunService runService) : IHunterRunController
{
    private readonly object _gate = new();
    private CancellationTokenSource? _runCancellation;
    private Task<HunterRunResult>? _activeTask;
    public HunterRunStatus Status { get; private set; } = HunterRunStatus.Idle;
    public bool IsRunActive => Status is HunterRunStatus.Preparing or HunterRunStatus.Running or HunterRunStatus.Cancelling;

    public Task<HunterRunResult> StartAsync(HunterRunConfiguration configuration, IHunterRunObserver observer,
        CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (IsRunActive) throw new InvalidOperationException("A hunter run is already active.");
            _runCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Status = HunterRunStatus.Preparing;
            _activeTask = ExecuteAsync(configuration, observer, _runCancellation);
            return _activeTask;
        }
    }

    public async Task CancelAsync()
    {
        Task<HunterRunResult>? task;
        lock (_gate)
        {
            if (!IsRunActive || _runCancellation is null) return;
            Status = HunterRunStatus.Cancelling;
            _runCancellation.Cancel(); task = _activeTask;
        }
        if (task is not null) await task;
    }

    private async Task<HunterRunResult> ExecuteAsync(HunterRunConfiguration configuration, IHunterRunObserver observer,
        CancellationTokenSource cancellation)
    {
        try
        {
            Status = HunterRunStatus.Running;
            var result = await runService.RunAsync(configuration, observer, cancellation.Token);
            Status = result.Summary.Status;
            return result;
        }
        finally
        {
            cancellation.Dispose();
            lock (_gate) { _runCancellation = null; _activeTask = null; }
        }
    }
}

public sealed class HunterRunService(
    IProxySourceLoader sourceLoader,
    IEnumerable<IProxyParser> parsers,
    IProxyNormalizer normalizer,
    IProxyProtocolDetector protocolDetector,
    ISourceHealthEvaluator healthEvaluator,
    ISourceContentFingerprintService fingerprintService,
    ITikTokCapabilityVerifier capabilityVerifier,
    IExitIpResolver exitIpResolver,
    IProxyGeoResolver geoResolver,
    IProxyPreScorer preScorer,
    IProxyScorer scorer,
    IAdvancedBrowserProxyVerifier browserVerifier,
    Stage2ResultExporter exporter,
    IRunCheckpointStore checkpointStore,
    HunterOptions baseHunterOptions,
    GeoOptions baseGeoOptions,
    TikTokVerificationOptions tikTokOptions,
    StabilityOptions baseStabilityOptions,
    PipelineLimits pipelineLimits) : IHunterRunService
{
    public async Task<HunterRunResult> RunAsync(HunterRunConfiguration configuration,
        IHunterRunObserver observer, CancellationToken cancellationToken)
    {
        Validate(configuration);
        var runId = Guid.NewGuid(); var started = DateTimeOffset.UtcNow;
        var output = Path.GetFullPath(configuration.OutputDirectory); Directory.CreateDirectory(output);
        var sink = new HunterProgressSink(observer); var currentStage = HunterUiStage.Preparing;
        var checks = new ConcurrentDictionary<string, ProxyCheckResult>(StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<ProxySourceHealth> sourceHealth = [];
        long collected = 0; long unique = 0;
        var runOptions = baseHunterOptions with
        {
            MaximumCandidates = configuration.MaximumCandidates,
            ProbeConcurrency = Math.Max(1, configuration.Concurrency),
            ProxyConnectTimeoutSeconds = Math.Max(1, configuration.TimeoutSeconds),
            TikTokRequestTimeoutSeconds = Math.Max(1, configuration.TimeoutSeconds)
        };
        var runGeo = baseGeoOptions with
        {
            AllowUnknownCountryForFastCheck = configuration.AllowUnknownGeoForTechnicalCheck,
            AllowConflictingCountryForFastCheck = configuration.AllowConflictingGeoForTechnicalCheck,
            RejectLikelyCountryCodes = configuration.RejectLikelyRussia ? ["RU"] : [],
            MinimumConfidenceForRecommendation = configuration.MinimumGeoConfidenceForRecommendation
        };
        var runStability = baseStabilityOptions with { Attempts = Math.Max(1, configuration.StabilityAttempts) };
        var hash = RunCheckpointStore.ComputeConfigurationHash(configuration.SourcesPath,
            configuration.MaximumCandidates.ToString(System.Globalization.CultureInfo.InvariantCulture),
            configuration.TimeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
            string.Join('|', configuration.PublicVideoUrls.Select(x => x.GetLeftPart(UriPartial.Path))),
            configuration.BrowserVerificationEnabled.ToString(),
            configuration.AllowUnknownGeoForTechnicalCheck.ToString(),
            configuration.AllowConflictingGeoForTechnicalCheck.ToString(),
            configuration.RejectLikelyRussia.ToString(),
            configuration.MinimumGeoConfidenceForRecommendation.ToString(),
            configuration.StabilityAttempts.ToString(System.Globalization.CultureInfo.InvariantCulture),
            configuration.BrowserLimit.ToString(System.Globalization.CultureInfo.InvariantCulture));

        await PublishAsync(sink, runId, HunterProgressEvent.RunStarted, HunterRunStatus.Preparing,
            null, "Подготовка запуска", cancellationToken);
        try
        {
            var definitions = await StageAsync(HunterUiStage.LoadingSources, null, async () =>
            {
                var values = await sourceLoader.LoadDefinitionsAsync(configuration.SourcesPath, cancellationToken);
                var enabled = values.Where(x => x.Enabled).ToArray();
                var payloads = await sourceLoader.LoadEnabledAsync(enabled, cancellationToken);
                return (All: values, Enabled: enabled, Payloads: payloads);
            });

            currentStage = HunterUiStage.Normalizing;
            await StageStartedAsync(currentStage, null);
            var processor = new StreamingCandidateProcessor(parsers, normalizer, runOptions);
            var byName = definitions.Enabled.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
            var collection = await processor.ProcessAsync(definitions.Payloads.Where(x => byName.ContainsKey(x.SourceName))
                .Select(x => (byName[x.SourceName], x)), cancellationToken);
            collected = collection.Candidates; unique = collection.Endpoints.Count;
            sourceHealth = BuildHealth(definitions.All, definitions.Payloads, collection);
            await StageCompletedAsync(currentStage, collection.Candidates, collection.Endpoints.Count,
                collection.Candidates - collection.Endpoints.Count, sourceHealth.Any(x => x.Status is not (ProxySourceHealthStatus.Healthy or ProxySourceHealthStatus.Disabled)));

            var resume = await LoadResumeAsync(configuration, hash, cancellationToken);
            foreach (var item in resume) checks[item.Endpoint.NormalizedKey] = item;

            currentStage = HunterUiStage.ProbingProtocols;
            var probeInput = collection.Endpoints.OrderByDescending(x => x.SourceFamilies.Count)
                .ThenBy(x => x.NormalizedKey, StringComparer.OrdinalIgnoreCase).ToArray();
            await StageStartedAsync(currentStage, probeInput.Length);
            var completed = resume.Select(x => x.Endpoint.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var pending = probeInput.Where(x => !completed.Contains(x.NormalizedKey)).ToArray();
            var probePipeline = new StreamingProbePipeline(protocolDetector, runOptions);
            var processed = completed.Count; var aliveCount = resume.Count(x => x.Probe?.Success == true); var probeWatch = Stopwatch.StartNew();
            foreach (var batch in pending.Chunk(Math.Max(50, runOptions.ProbeConcurrency * 2)))
            {
                var probed = await probePipeline.ProbeAsync(batch, null, cancellationToken);
                foreach (var value in probed) { checks[value.Endpoint.NormalizedKey] = value; if (value.Probe?.Success == true) aliveCount++; }
                processed += probed.Count;
                await StageProgressAsync(currentStage, processed, probeInput.Length, aliveCount, processed - aliveCount, probeWatch.Elapsed);
            }
            await StageCompletedAsync(currentStage, processed, aliveCount, processed - aliveCount, false);

            var alive = checks.Values.Where(x => x.Probe?.Success == true).Select(x => x with { PreScore = preScorer.Calculate(x) }).ToArray();
            foreach (var item in alive) checks[item.Endpoint.NormalizedKey] = item;
            var fastInput = DeterministicPipelineLimiter.Take(alive.Where(x => x.Endpoint.DetectedProtocol != ProxyProtocol.Http),
                pipelineLimits.MaximumFastTikTokChecks).ToArray();

            currentStage = HunterUiStage.CheckingHttps;
            await StageStartedAsync(currentStage, fastInput.Length);
            var fastProcessed = 0; var genericPassed = 0; var fastWatch = Stopwatch.StartNew();
            await Parallel.ForEachAsync(fastInput, ParallelOptions(runOptions, cancellationToken), async (check, token) =>
            {
                var generic = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.ShortGenericHttps, null, token);
                var homepage = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.TikTokHomepage, null, token);
                var mobile = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.TikTokMobilePage, null, token);
                var value = check with { TikTokCapabilities = [generic, homepage, mobile] };
                checks[check.Endpoint.NormalizedKey] = value;
                if (generic.Status == TikTokCapabilityStatus.Passed) Interlocked.Increment(ref genericPassed);
                var done = Interlocked.Increment(ref fastProcessed);
                await StageProgressAsync(currentStage, done, fastInput.Length, Volatile.Read(ref genericPassed),
                    done - Volatile.Read(ref genericPassed), fastWatch.Elapsed);
            });
            await StageCompletedAsync(currentStage, fastProcessed, genericPassed, fastProcessed - genericPassed, false);

            currentStage = HunterUiStage.CheckingTikTok;
            var homepagePassed = checks.Values.Where(x => Passed(x, TikTokCapability.TikTokHomepage)).ToArray();
            await StageStartedAsync(currentStage, fastInput.Length);
            await StageCompletedAsync(currentStage, fastInput.Length, homepagePassed.Length,
                fastInput.Length - homepagePassed.Length, false);

            currentStage = HunterUiStage.ResolvingExitIp;
            var exitInput = DeterministicPipelineLimiter.Take(fastInput.Select(x => checks[x.Endpoint.NormalizedKey]),
                pipelineLimits.MaximumExitIpChecks).ToArray();
            await StageStartedAsync(currentStage, exitInput.Length);
            var exitProcessed = 0; var exitPassed = 0; var exitWatch = Stopwatch.StartNew();
            await Parallel.ForEachAsync(exitInput, ParallelOptions(runOptions with { ProbeConcurrency = Math.Min(32, runOptions.ProbeConcurrency) }, cancellationToken), async (check, token) =>
            {
                var exit = await exitIpResolver.ResolveAsync(check.Endpoint, token);
                var value = check with { ExitIp = exit }; value = value with { PreScore = preScorer.Calculate(value) };
                checks[check.Endpoint.NormalizedKey] = value;
                if (exit.Status == ExitIpStatus.Resolved) Interlocked.Increment(ref exitPassed);
                var done = Interlocked.Increment(ref exitProcessed);
                await StageProgressAsync(currentStage, done, exitInput.Length, Volatile.Read(ref exitPassed),
                    done - Volatile.Read(ref exitPassed), exitWatch.Elapsed);
            });
            await StageCompletedAsync(currentStage, exitProcessed, exitPassed, exitProcessed - exitPassed, false);

            currentStage = HunterUiStage.ResolvingGeo;
            var geoInput = checks.Values.Where(x => x.ExitIp is { Status: ExitIpStatus.Resolved, ExitIp: not null }).ToArray();
            await StageStartedAsync(currentStage, geoInput.Length);
            var geoProcessed = 0; var geoPassed = 0; var geoWatch = Stopwatch.StartNew();
            await Parallel.ForEachAsync(geoInput, ParallelOptions(runOptions with { ProbeConcurrency = Math.Min(16, runOptions.ProbeConcurrency) }, cancellationToken), async (check, token) =>
            {
                var geo = await geoResolver.ResolveAsync(check.ExitIp!.ExitIp!, token);
                var value = check with { Geo = geo }; value = value with { PreScore = preScorer.Calculate(value) };
                checks[check.Endpoint.NormalizedKey] = value;
                if (geo.Status is ProxyGeoStatus.Resolved or ProxyGeoStatus.GeoUncertain) Interlocked.Increment(ref geoPassed);
                var done = Interlocked.Increment(ref geoProcessed);
                await StageProgressAsync(currentStage, done, geoInput.Length, Volatile.Read(ref geoPassed),
                    done - Volatile.Read(ref geoPassed), geoWatch.Elapsed);
            });
            await StageCompletedAsync(currentStage, geoProcessed, geoPassed, geoProcessed - geoPassed, false);

            currentStage = HunterUiStage.CheckingStability;
            var stabilityInput = DeterministicPipelineLimiter.Take(checks.Values.Where(x => Passed(x, TikTokCapability.TikTokHomepage)),
                pipelineLimits.MaximumStabilityChecks).ToArray();
            await StageStartedAsync(currentStage, stabilityInput.Length);
            var stabilityChecker = new ProxyStabilityChecker(capabilityVerifier, runStability);
            var stabilityProcessed = 0; var stableCount = 0; var stabilityWatch = Stopwatch.StartNew();
            await Parallel.ForEachAsync(stabilityInput, ParallelOptions(runOptions with { ProbeConcurrency = Math.Min(10, runOptions.ProbeConcurrency) }, cancellationToken), async (check, token) =>
            {
                var stability = await stabilityChecker.CheckAsync(check.Endpoint, TikTokCapability.TikTokHomepage, null, token);
                checks[check.Endpoint.NormalizedKey] = check with { Stability = stability, TikTokPageStability = stability };
                if (stability.Status == ProxyStabilityStatus.Stable) Interlocked.Increment(ref stableCount);
                var done = Interlocked.Increment(ref stabilityProcessed);
                await StageProgressAsync(currentStage, done, stabilityInput.Length, Volatile.Read(ref stableCount),
                    done - Volatile.Read(ref stableCount), stabilityWatch.Elapsed);
            });
            await StageCompletedAsync(currentStage, stabilityProcessed, stableCount, stabilityProcessed - stableCount, false);

            currentStage = HunterUiStage.CheckingVideo;
            var videoInput = DeterministicPipelineLimiter.Take(checks.Values.Where(x => Passed(x, TikTokCapability.TikTokHomepage)
                || Passed(x, TikTokCapability.ShortGenericHttps)), pipelineLimits.MaximumVideoPageChecks).ToArray();
            await StageStartedAsync(currentStage, videoInput.Length);
            if (configuration.PublicVideoUrls.Count == 0)
            {
                foreach (var check in videoInput) checks[check.Endpoint.NormalizedKey] = AddCapabilities(check,
                    NotConfigured(TikTokCapability.TikTokPostPage), NotConfigured(TikTokCapability.TikTokOEmbed),
                    NotConfigured(TikTokCapability.TikTokEmbedPlayer));
                await StageSkippedAsync(currentStage, videoInput.Length, "Публичное TikTok-видео не настроено");
            }
            else
            {
                var video = configuration.PublicVideoUrls[0]; var videoProcessed = 0; var videoPassed = 0; var videoWatch = Stopwatch.StartNew();
                await Parallel.ForEachAsync(videoInput, ParallelOptions(runOptions with { ProbeConcurrency = Math.Min(8, runOptions.ProbeConcurrency) }, cancellationToken), async (check, token) =>
                {
                    var post = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.TikTokPostPage, video, token);
                    var oembed = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.TikTokOEmbed, video, token);
                    var embed = await capabilityVerifier.VerifyCapabilityAsync(check.Endpoint, TikTokCapability.TikTokEmbedPlayer, video, token);
                    checks[check.Endpoint.NormalizedKey] = AddCapabilities(check, post, oembed, embed);
                    if (post.Status == TikTokCapabilityStatus.Passed || embed.Status == TikTokCapabilityStatus.Passed) Interlocked.Increment(ref videoPassed);
                    var done = Interlocked.Increment(ref videoProcessed);
                    await StageProgressAsync(currentStage, done, videoInput.Length, Volatile.Read(ref videoPassed),
                        done - Volatile.Read(ref videoPassed), videoWatch.Elapsed);
                });
                await StageCompletedAsync(currentStage, videoProcessed, videoPassed, videoProcessed - videoPassed, false);
            }

            currentStage = HunterUiStage.CheckingBrowser;
            if (!configuration.BrowserVerificationEnabled || configuration.PublicVideoUrls.Count == 0)
                await StageSkippedAsync(currentStage, 0, configuration.PublicVideoUrls.Count == 0
                    ? "Публичное TikTok-видео не настроено" : "Браузерная проверка выключена");
            else
            {
                var browserInput = DeterministicPipelineLimiter.Take(checks.Values.Where(x => Passed(x, TikTokCapability.TikTokHomepage)
                    || Passed(x, TikTokCapability.TikTokEmbedPlayer)), Math.Min(configuration.BrowserLimit, pipelineLimits.MaximumBrowserChecks)).ToArray();
                await StageStartedAsync(currentStage, browserInput.Length);
                var browserProcessed = 0; var browserPassed = 0; var browserWatch = Stopwatch.StartNew();
                await Parallel.ForEachAsync(browserInput, new ParallelOptions { MaxDegreeOfParallelism = 2, CancellationToken = cancellationToken }, async (check, token) =>
                {
                    var original = await browserVerifier.VerifyAsync(check.Endpoint, configuration.PublicVideoUrls[0], BrowserVerificationMode.OriginalPostPage, token);
                    var embed = await browserVerifier.VerifyAsync(check.Endpoint, configuration.PublicVideoUrls[0], BrowserVerificationMode.OfficialEmbedPlayer, token);
                    checks[check.Endpoint.NormalizedKey] = check with { BrowserVerification = original, BrowserPlayback = new()
                    { OriginalPostPlaybackResult = original, EmbedPlayerPlaybackResult = embed } };
                    if (original.Status == BrowserVerificationStatus.Passed || embed.Status == BrowserVerificationStatus.Passed) Interlocked.Increment(ref browserPassed);
                    var done = Interlocked.Increment(ref browserProcessed);
                    await StageProgressAsync(currentStage, done, browserInput.Length, Volatile.Read(ref browserPassed),
                        done - Volatile.Read(ref browserPassed), browserWatch.Elapsed);
                });
                await StageCompletedAsync(currentStage, browserProcessed, browserPassed, browserProcessed - browserPassed, false);
            }

            currentStage = HunterUiStage.Exporting;
            await StageStartedAsync(currentStage, checks.Count);
            var final = checks.Values.Select(x =>
            {
                var prescored = x with { PreScore = preScorer.Calculate(x) };
                var scored = prescored with { Score = scorer.Calculate(prescored) };
                return CapabilityDecisionEngine.Evaluate(scored, runGeo, tikTokOptions, tikTokOptions.MaximumRecommendedLatencyMs);
            }).OrderByDescending(x => x.Score.Value).ThenBy(x => x.Endpoint.NormalizedKey).ToArray();
            var summary = CreateSummary(runId, HunterRunStatus.Completed, started, output, collected, unique, final, null);
            await PersistAsync(configuration, hash, summary, final, sourceHealth, output, cancellationToken);
            await StageCompletedAsync(currentStage, final.Length, final.Length, 0, false);
            await PublishAsync(sink, runId, HunterProgressEvent.RunCompleted, HunterRunStatus.Completed, null,
                $"Завершено. TikTok доступен через {summary.TikTokAccessible:N0} прокси", cancellationToken);
            return new() { Summary = summary, Results = final, SourceHealth = sourceHealth };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            var final = EvaluatePartial(checks.Values, runGeo); var summary = CreateSummary(runId, HunterRunStatus.Cancelled,
                started, output, collected, unique, final, null);
            await PersistAsync(configuration, hash, summary, final, sourceHealth, output, CancellationToken.None);
            await PublishAsync(sink, runId, HunterProgressEvent.RunCancelled, HunterRunStatus.Cancelled,
                new() { Stage = currentStage, Status = HunterStageStatus.Cancelled }, "Остановлено пользователем", CancellationToken.None);
            return new() { Summary = summary, Results = final, SourceHealth = sourceHealth };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or HttpRequestException
            or InvalidDataException or InvalidOperationException)
        {
            var failure = new HunterRunFailure { UserMessage = "Не удалось завершить поиск прокси",
                TechnicalType = ex.GetType().Name, TechnicalMessage = SensitiveData.RedactProxyUri(ex.Message), Stage = currentStage };
            var final = EvaluatePartial(checks.Values, runGeo); var summary = CreateSummary(runId, HunterRunStatus.Failed,
                started, output, collected, unique, final, failure);
            await PersistAsync(configuration, hash, summary, final, sourceHealth, output, CancellationToken.None);
            await PublishAsync(sink, runId, HunterProgressEvent.RunFailed, HunterRunStatus.Failed,
                new() { Stage = currentStage, Status = HunterStageStatus.Failed }, failure.UserMessage, CancellationToken.None);
            return new() { Summary = summary, Results = final, SourceHealth = sourceHealth };
        }

        async Task<T> StageAsync<T>(HunterUiStage stage, long? total, Func<Task<T>> action)
        {
            currentStage = stage; await StageStartedAsync(stage, total); var watch = Stopwatch.StartNew();
            var result = await action(); await StageCompletedAsync(stage, total ?? 1, total ?? 1, 0, false, watch.Elapsed); return result;
        }
        async ValueTask StageStartedAsync(HunterUiStage stage, long? total) => await PublishAsync(sink, runId,
            HunterProgressEvent.StageStarted, HunterRunStatus.Running, new() { Stage = stage, Status = HunterStageStatus.Running, Total = total }, null, cancellationToken);
        async ValueTask StageProgressAsync(HunterUiStage stage, long processed, long total, long passed, long rejected, TimeSpan elapsed) =>
            await PublishAsync(sink, runId, HunterProgressEvent.StageProgress, HunterRunStatus.Running,
                Progress(stage, HunterStageStatus.Running, processed, total, passed, rejected, elapsed), null, cancellationToken);
        async ValueTask StageCompletedAsync(HunterUiStage stage, long processed, long passed, long rejected, bool warnings, TimeSpan? elapsed = null) =>
            await PublishAsync(sink, runId, HunterProgressEvent.StageCompleted, HunterRunStatus.Running,
                Progress(stage, warnings ? HunterStageStatus.CompletedWithWarnings : HunterStageStatus.Completed,
                    processed, processed, passed, rejected, elapsed ?? TimeSpan.Zero), null, cancellationToken);
        async ValueTask StageSkippedAsync(HunterUiStage stage, long total, string reason) => await PublishAsync(sink, runId,
            HunterProgressEvent.StageCompleted, HunterRunStatus.Running,
            new() { Stage = stage, Status = HunterStageStatus.Skipped, Total = total }, reason, cancellationToken);
    }

    private async Task<IReadOnlyList<ProxyCheckResult>> LoadResumeAsync(HunterRunConfiguration configuration,
        string hash, CancellationToken token)
    {
        if (!configuration.Resume || string.IsNullOrWhiteSpace(configuration.ResumeRunDirectory)) return [];
        var directory = Path.GetFullPath(configuration.ResumeRunDirectory);
        var checkpoint = await checkpointStore.LoadAsync(Path.Combine(directory, "run-checkpoint.json"), token);
        var statePath = Path.Combine(directory, "run-state.private.json");
        if (!RunCheckpointStore.CanResume(checkpoint, hash) || !File.Exists(statePath)) return [];
        return JsonSerializer.Deserialize<List<ProxyCheckResult>>(await File.ReadAllTextAsync(statePath, token), JsonDefaults.Options) ?? [];
    }

    private IReadOnlyList<ProxySourceHealth> BuildHealth(IReadOnlyList<ProxySourceDefinition> definitions,
        IReadOnlyList<ProxySourceResult> results, StreamingCollectionResult collection)
    {
        var health = definitions.Select(definition =>
        {
            var result = results.FirstOrDefault(x => x.SourceName.Equals(definition.Name, StringComparison.OrdinalIgnoreCase))
                ?? new ProxySourceResult { SourceName = definition.Name, Error = definition.Enabled ? "No source result" : null };
            collection.SourceCounts.TryGetValue(definition.Name, out var count);
            return healthEvaluator.Evaluate(definition, result, count.Extracted, count.Valid, result.Success ? 0 : 1);
        }).ToArray();
        var mirrors = fingerprintService.FindExactMirrors(health);
        return health.Select(x => mirrors.TryGetValue(x.SourceName, out var duplicate)
            ? x with { DuplicateOf = duplicate, Status = ProxySourceHealthStatus.Degraded } : x).ToArray();
    }

    private async Task PersistAsync(HunterRunConfiguration configuration, string hash, HunterRunSummary summary,
        IReadOnlyList<ProxyCheckResult> results, IReadOnlyList<ProxySourceHealth> health, string output, CancellationToken token)
    {
        Directory.CreateDirectory(output);
        var checkpoint = new RunCheckpoint { ConfigurationHash = hash, Stage = summary.Status.ToString(),
            CompletedEndpointKeys = results.Select(x => x.Endpoint.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase),
            ProbedEndpointKeys = results.Where(x => x.Probe is not null).Select(x => x.Endpoint.NormalizedKey).ToHashSet(StringComparer.OrdinalIgnoreCase) };
        await File.WriteAllTextAsync(Path.Combine(output, "run-state.private.json"), JsonSerializer.Serialize(results, JsonDefaults.Options), token);
        await exporter.ExportStage2Async(output, results, health, checkpoint, token);
        await exporter.ExportCapabilityMatrixAsync(output, CapabilityMatrixBuilder.Build(results), token);
        await exporter.ExportUserListsAsync(Path.Combine(output, "user-proxies"), results, baseGeoOptions,
            configuration.BrowserVerificationEnabled, token);
        await checkpointStore.SaveAsync(Path.Combine(output, "run-checkpoint.json"), checkpoint, token);
        var manifest = new HunterRunManifest { RunId = summary.RunId, Configuration = Sanitize(configuration), Summary = summary,
            ConfigurationHash = hash, AppVersion = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0" };
        await AtomicJson.WriteAsync(Path.Combine(output, "run-manifest.json"), manifest, token);
    }

    private ProxyCheckResult[] EvaluatePartial(IEnumerable<ProxyCheckResult> source, GeoOptions options) => source.Select(x =>
    {
        var value = x with { PreScore = preScorer.Calculate(x), Score = scorer.Calculate(x) };
        return CapabilityDecisionEngine.Evaluate(value, options, tikTokOptions, tikTokOptions.MaximumRecommendedLatencyMs);
    }).OrderByDescending(x => x.Score.Value).ToArray();

    private static HunterRunSummary CreateSummary(Guid runId, HunterRunStatus status, DateTimeOffset started, string output,
        long collected, long unique, IReadOnlyList<ProxyCheckResult> results, HunterRunFailure? failure) => new()
    {
        RunId = runId, Status = status, StartedAt = started, FinishedAt = DateTimeOffset.UtcNow, OutputDirectory = output,
        Collected = collected, Unique = unique, ProtocolAlive = results.Count(x => x.Probe?.Success == true),
        GenericHttpsPassed = results.Count(x => Passed(x, TikTokCapability.ShortGenericHttps)),
        TikTokAccessible = results.Count(x => Passed(x, TikTokCapability.TikTokHomepage) || Passed(x, TikTokCapability.TikTokEmbedPlayer)),
        Stable = results.Count(x => (x.TikTokPageStability ?? x.Stability)?.Status == ProxyStabilityStatus.Stable),
        PlaybackVerified = results.Count(x => x.PlaybackCapability is PlaybackCapability.EmbedPlaybackVerified or PlaybackCapability.FullPlaybackVerified),
        Recommended = results.Count(x => x.RecommendationClass == ProxyRecommendationClass.Recommended),
        RejectedRussia = results.Count(x => x.Geo?.Decision is GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia), Failure = failure
    };

    private static HunterRunConfiguration Sanitize(HunterRunConfiguration value) => value with
    { PublicVideoUrls = value.PublicVideoUrls.Select(TikTokVideoUrlParser.Sanitize).ToArray() };
    private static ParallelOptions ParallelOptions(HunterOptions options, CancellationToken token) => new()
    { MaxDegreeOfParallelism = Math.Max(1, options.ProbeConcurrency), CancellationToken = token };
    private static HunterStageProgress Progress(HunterUiStage stage, HunterStageStatus status, long processed, long total,
        long passed, long rejected, TimeSpan elapsed) => new() { Stage = stage, Status = status, Processed = processed,
            Total = total, Passed = passed, Rejected = rejected, Elapsed = elapsed,
            ItemsPerSecond = elapsed.TotalSeconds <= 0 ? 0 : processed / elapsed.TotalSeconds };
    private static bool Passed(ProxyCheckResult value, TikTokCapability capability) =>
        value.TikTokCapabilities.Any(x => x.Capability == capability && x.Status == TikTokCapabilityStatus.Passed);
    private static TikTokCapabilityResult NotConfigured(TikTokCapability capability) => new()
    { Capability = capability, Status = TikTokCapabilityStatus.NotConfigured,
      Reason = $"{CapabilityNotRunReason.NotConfigured}: no enabled public TikTok test video" };
    private static ProxyCheckResult AddCapabilities(ProxyCheckResult check, params TikTokCapabilityResult[] additions)
    {
        var capabilities = additions.Select(x => x.Capability).ToHashSet();
        return check with { TikTokCapabilities = check.TikTokCapabilities.Where(x => !capabilities.Contains(x.Capability)).Concat(additions).ToArray() };
    }
    private static void Validate(HunterRunConfiguration configuration)
    {
        if (configuration.MaximumCandidates <= 0) throw new ArgumentOutOfRangeException(nameof(configuration), "MaximumCandidates must be positive.");
        if (configuration.Concurrency <= 0) throw new ArgumentOutOfRangeException(nameof(configuration), "Concurrency must be positive.");
        if (configuration.BrowserVerificationEnabled && configuration.PublicVideoUrls.Count == 0)
            throw new ArgumentException("Browser verification requires a public TikTok video URL.", nameof(configuration));
    }
    private static ValueTask PublishAsync(IHunterProgressSink sink, Guid runId, HunterProgressEvent eventType,
        HunterRunStatus status, HunterStageProgress? stage, string? message, CancellationToken token) =>
        sink.PublishAsync(new() { RunId = runId, Event = eventType, Status = status, Stage = stage, Message = message }, token);
}

public static class AtomicJson
{
    public static async Task WriteAsync<T>(string path, T value, CancellationToken token)
    {
        var fullPath = Path.GetFullPath(path); Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var temporary = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16_384, FileOptions.Asynchronous | FileOptions.WriteThrough))
                await JsonSerializer.SerializeAsync(stream, value, JsonDefaults.Options, token);
            File.Move(temporary, fullPath, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
