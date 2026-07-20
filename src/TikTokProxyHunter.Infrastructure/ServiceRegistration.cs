using Microsoft.Extensions.DependencyInjection;
using System.Net;
using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Infrastructure;

public static class ServiceRegistration
{
    public static IServiceCollection AddProxyHunterInfrastructure(this IServiceCollection services, HunterOptions options,
        GeoOptions? geoOptions = null, ExitIpOptions? exitIpOptions = null,
        TikTokVerificationOptions? tikTokOptions = null, StabilityOptions? stabilityOptions = null,
        BrowserVerificationOptions? browserOptions = null, GitHubDiscoveryOptions? discoveryOptions = null,
        PipelineLimits? pipelineLimits = null, ProxyPreScoreWeights? preScoreWeights = null,
        ResultTtlOptions? resultTtlOptions = null)
    {
        geoOptions ??= new GeoOptions(); exitIpOptions ??= new ExitIpOptions(); tikTokOptions ??= new TikTokVerificationOptions();
        stabilityOptions ??= new StabilityOptions(); browserOptions ??= new BrowserVerificationOptions(); discoveryOptions ??= new GitHubDiscoveryOptions();
        pipelineLimits ??= new PipelineLimits(); preScoreWeights ??= new ProxyPreScoreWeights();
        resultTtlOptions ??= new ResultTtlOptions();
        services.AddSingleton(options);
        services.AddSingleton(geoOptions); services.AddSingleton(exitIpOptions); services.AddSingleton(tikTokOptions);
        services.AddSingleton(stabilityOptions); services.AddSingleton(browserOptions); services.AddSingleton(discoveryOptions);
        services.AddSingleton(pipelineLimits); services.AddSingleton(preScoreWeights);
        services.AddSingleton(resultTtlOptions);
        services.AddHttpClient("proxy-sources", client =>
        {
            client.Timeout = Timeout.InfiniteTimeSpan;
            client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            AllowAutoRedirect = true, MaxAutomaticRedirections = 5
        });
        services.AddHttpClient("github-discovery", client =>
        {
            client.BaseAddress = new Uri("https://api.github.com/"); client.Timeout = TimeSpan.FromSeconds(20);
            client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
        });
        services.AddHttpClient("github-raw-discovery", client => { client.Timeout = TimeSpan.FromSeconds(20); client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent); });
        services.AddHttpClient("exit-ip-direct", client => { client.Timeout = TimeSpan.FromSeconds(10); client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent); });
        services.AddHttpClient("geo-providers", client => { client.Timeout = Timeout.InfiniteTimeSpan; client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent); });
        services.AddHttpClient("tiktok-video-validation", client => { client.Timeout = TimeSpan.FromSeconds(20); client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent); })
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { UseCookies = false, AllowAutoRedirect = true, MaxAutomaticRedirections = 5 });
        services.AddSingleton<ISourceContentFingerprintService, SourceContentFingerprintService>();
        services.AddSingleton<ISourceHealthEvaluator, SourceHealthEvaluator>();
        services.AddSingleton<SourcePayloadCache>();
        services.AddSingleton<IProxySource, LocalFileProxySource>();
        services.AddSingleton<IProxySource, TextProxySource>();
        services.AddSingleton<IProxySource, CsvProxySource>();
        services.AddSingleton<IProxySource, JsonProxySource>();
        services.AddSingleton<IProxySource, HtmlProxySource>();
        services.AddSingleton<IProxyParser, TextProxyParser>();
        services.AddSingleton<IProxyParser, CsvProxyParser>();
        services.AddSingleton<IProxyParser, JsonProxyParser>();
        services.AddSingleton<IProxyParser, HtmlProxyParser>();
        services.AddSingleton<IProxySourceLoader, ProxySourceLoader>();
        services.AddSingleton<IProxyNormalizer>(_ => new ProxyNormalizer(new NormalizationOptions(options.AllowPrivateAddresses)));
        services.AddSingleton<IProxyDeduplicator, ProxyDeduplicator>();
        services.AddSingleton<IProxyProbe, ProxyProbe>();
        services.AddSingleton<IProxyProtocolDetector, ProxyProtocolDetector>();
        services.AddSingleton<ITikTokChecker, TikTokChecker>();
        services.AddSingleton<IProxyScorer>(_ => new ProxyScorer(options.Score, geoOptions.PreferredCountryCodes, geoOptions, tikTokOptions.MobilePage));
        services.AddSingleton<IResultExporter, ResultExporter>();
        services.AddSingleton<ProxyHttpsClient>();
        services.AddSingleton<ProxyHttpClient>();
        services.AddSingleton<ExitIpConsensusService>();
        services.AddSingleton<ExitIpProviderCircuitBreaker>();
        services.AddSingleton<IExitIpResolver, ExitIpResolver>();
        services.AddSingleton<IExitIpProviderDiagnostics>(sp => (ExitIpResolver)sp.GetRequiredService<IExitIpResolver>());
        services.AddSingleton<GeoConsensusService>();
        services.AddSingleton<ILocalGeoIpProvider, LocalGeoIpProvider>();
        services.AddSingleton<IProxyGeoResolver, ProxyGeoResolver>();
        services.AddSingleton<IProxyPreScorer, ProxyPreScorer>();
        services.AddSingleton<ITikTokCapabilityVerifier, TikTokCapabilityVerifier>();
        services.AddSingleton<ITikTokEmbedPlayerVerifier, TikTokEmbedPlayerVerifier>();
        services.AddSingleton<TikTokVideoValidationService>();
        services.AddSingleton<IProxyStabilityChecker, ProxyStabilityChecker>();
        services.AddSingleton<IBrowserProxyVerifier, PlaywrightBrowserProxyVerifier>();
        services.AddSingleton<IAdvancedBrowserProxyVerifier>(sp => (PlaywrightBrowserProxyVerifier)sp.GetRequiredService<IBrowserProxyVerifier>());
        services.AddSingleton<IBrowserDoctor, BrowserDoctor>();
        services.AddSingleton<IGitHubSourceDiscoveryService, GitHubSourceDiscoveryService>();
        services.AddSingleton<IRunCheckpointStore, RunCheckpointStore>();
        services.AddSingleton<Stage2ResultExporter>();
        services.AddSingleton<StreamingCandidateProcessor>();
        services.AddSingleton<StreamingProbePipeline>();
        services.AddSingleton<IHunterRunService, HunterRunService>();
        services.AddSingleton<IHunterRunController, HunterRunController>();
        return services;
    }
}
