using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TikTokProxyHunter.App;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Infrastructure;

var cli = CliOptions.Parse(args);
if (cli.ShowHelp)
{
    CliOptions.PrintHelp();
    return 0;
}
var runOutput = cli.OutputPath ?? Path.Combine("output", DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmss.fffZ"));
cli = cli with { OutputPath = runOutput };
Directory.CreateDirectory(runOutput);

var builder = Host.CreateApplicationBuilder(args);
builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);
var hunterOptions = builder.Configuration.GetSection("Hunter").Get<HunterOptions>() ?? new HunterOptions();
var geoOptions = builder.Configuration.GetSection("Geo").Get<GeoOptions>() ?? new GeoOptions();
var exitIpOptions = builder.Configuration.GetSection("ExitIp").Get<ExitIpOptions>() ?? new ExitIpOptions();
var tikTokOptions = builder.Configuration.GetSection("TikTok").Get<TikTokVerificationOptions>() ?? new TikTokVerificationOptions();
var stabilityOptions = builder.Configuration.GetSection("Stability").Get<StabilityOptions>() ?? new StabilityOptions();
var browserOptions = builder.Configuration.GetSection("BrowserVerification").Get<BrowserVerificationOptions>() ?? new BrowserVerificationOptions();
if (!Path.IsPathRooted(browserOptions.ScreenshotDirectory)) browserOptions = browserOptions with
{ ScreenshotDirectory = Path.Combine(runOutput, browserOptions.ScreenshotDirectory) };
var discoveryOptions = builder.Configuration.GetSection("GitHubDiscovery").Get<GitHubDiscoveryOptions>() ?? new GitHubDiscoveryOptions();
var pipelineLimits = builder.Configuration.GetSection("PipelineLimits").Get<PipelineLimits>() ?? new PipelineLimits();
var preScoreWeights = builder.Configuration.GetSection("PreScore").Get<ProxyPreScoreWeights>() ?? new ProxyPreScoreWeights();
var resultTtlOptions = builder.Configuration.GetSection("ResultTtl").Get<ResultTtlOptions>() ?? new ResultTtlOptions();
if (cli.Concurrency is > 0) hunterOptions = hunterOptions with { ProbeConcurrency = cli.Concurrency.Value };
if (cli.TimeoutSeconds is > 0) hunterOptions = hunterOptions with
{
    ProxyConnectTimeoutSeconds = cli.TimeoutSeconds.Value,
    TikTokRequestTimeoutSeconds = cli.TimeoutSeconds.Value
};
if (cli.MaximumCandidates is >= 0) hunterOptions = hunterOptions with { MaximumCandidates = cli.MaximumCandidates.Value };
if (cli.RejectCountries.Count > 0) geoOptions = geoOptions with { RejectCountryCodes = cli.RejectCountries,
    RejectConfirmedCountryCodes = cli.RejectCountries, RejectLikelyCountryCodes = cli.RejectCountries };
if (cli.PreferredCountries.Count > 0) geoOptions = geoOptions with { PreferredCountryCodes = cli.PreferredCountries };
if (cli.AllowUnknownGeo is { } allowUnknown) geoOptions = geoOptions with
{ AllowUnknownCountryForFastCheck = allowUnknown, AllowUnknownCountryForBrowserCheck = allowUnknown };
if (cli.AllowConflictingGeo is { } allowConflicting) geoOptions = geoOptions with
{ AllowConflictingCountryForFastCheck = allowConflicting, AllowConflictingCountryForBrowserCheck = allowConflicting };
if (cli.RejectLikelyRu == false) geoOptions = geoOptions with { RejectLikelyCountryCodes = [] };
if (cli.RejectLikelyRu == true && geoOptions.RejectLikelyCountryCodes.Count == 0) geoOptions = geoOptions with { RejectLikelyCountryCodes = ["RU"] };
if (cli.MinimumGeoConfidence is { } confidence && Enum.TryParse<GeoConfidenceLevel>(confidence, true, out var minimumConfidence))
    geoOptions = geoOptions with { MinimumConfidenceForRecommendation = minimumConfidence };
else if (cli.MinimumGeoConfidence is not null) throw new ArgumentException($"Invalid --minimum-geo-confidence '{cli.MinimumGeoConfidence}'");
if (cli.GeoCountryDatabasePath is not null || cli.GeoAsnDatabasePath is not null) geoOptions = geoOptions with
{ LocalDatabase = geoOptions.LocalDatabase with { Enabled = true,
    CountryDatabasePath = cli.GeoCountryDatabasePath ?? geoOptions.LocalDatabase.CountryDatabasePath,
    AsnDatabasePath = cli.GeoAsnDatabasePath ?? geoOptions.LocalDatabase.AsnDatabasePath } };
if (cli.StabilityAttempts is > 0) stabilityOptions = stabilityOptions with { Attempts = cli.StabilityAttempts.Value };
if (cli.BrowserCheck) browserOptions = browserOptions with { Enabled = true };
if (cli.Command == "verify-browser-live") browserOptions = browserOptions with { Enabled = true };
if (cli.BrowserLimit is > 0) browserOptions = browserOptions with { MaximumCandidates = cli.BrowserLimit.Value };
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(x => { x.SingleLine = true; x.TimestampFormat = "HH:mm:ss "; });
builder.Logging.AddFilter("System.Net.Http.HttpClient", LogLevel.Warning);
builder.Logging.AddProvider(new FileLoggerProvider(Path.Combine(runOutput, "details.log")));
builder.Services.AddProxyHunterInfrastructure(hunterOptions, geoOptions, exitIpOptions, tikTokOptions,
    stabilityOptions, browserOptions, discoveryOptions, pipelineLimits, preScoreWeights, resultTtlOptions);
builder.Services.AddSingleton<PipelineRunner>();
builder.Services.AddSingleton<Stage2CommandRunner>();

using var host = builder.Build();
try
{
    return cli.IsStage2Command
        ? await host.Services.GetRequiredService<Stage2CommandRunner>().RunAsync(cli, CancellationToken.None)
        : await host.Services.GetRequiredService<PipelineRunner>().RunAsync(cli, CancellationToken.None);
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Operation cancelled.");
    return 2;
}
catch (Exception ex)
{
    host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Fatal").LogCritical(ex, "Run failed: {Reason}", ex.Message);
    return 1;
}
