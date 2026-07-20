namespace TikTokProxyHunter.Core;

public sealed class ProxyScorer : IProxyScorer
{
    private readonly ScoreWeights _weights;
    private readonly HashSet<string> _preferredCountries;
    private readonly GeoOptions? _geoOptions;
    private readonly TikTokMobilePageOptions? _mobileOptions;

    public ProxyScorer(ScoreWeights weights, IEnumerable<string>? preferredCountryCodes = null, GeoOptions? geoOptions = null,
        TikTokMobilePageOptions? mobileOptions = null)
    {
        _weights = weights;
        _preferredCountries = (preferredCountryCodes ?? []).ToHashSet(StringComparer.OrdinalIgnoreCase);
        _geoOptions = geoOptions;
        _mobileOptions = mobileOptions;
    }

    public ProxyScore Calculate(ProxyCheckResult result)
    {
        var reasons = new List<string>();
        if (result.Geo?.Decision is GeoResolutionDecision.ConfirmedRussia or GeoResolutionDecision.LikelyRussia
            || result.Geo is { Decision: GeoResolutionDecision.Unknown, CountryCode: "RU" })
            return new ProxyScore(0, ["Russian exit IP is rejected"]);
        if (result.BrowserVerification?.Status == BrowserVerificationStatus.TlsFailure
            || result.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.TlsFailure
            || result.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.TlsFailure)
            return new ProxyScore(0, ["TLS interception or certificate failure"]);
        if (result.TikTokChecks.Any(x => x.Status is TikTokStatus.TlsFailure or TikTokStatus.InvalidContent)
            || result.TikTokCapabilities.Any(x => x.Capability == TikTokCapability.TikTokHomepage
                && x.Status == TikTokCapabilityStatus.InvalidContent))
            return new ProxyScore(0, ["TLS failure or wrong destination content"]);

        var score = 0;
        if (result.TikTokChecks.Any(x => x.Status == TikTokStatus.Accessible)) Add(_weights.Accessible, "TikTok accessible");
        if (result.Endpoint.DetectedProtocol == ProxyProtocol.Socks5) Add(_weights.Socks5, "SOCKS5");
        if (result.Endpoint.DetectedProtocol == ProxyProtocol.HttpsConnect) Add(_weights.HttpConnect, "HTTP CONNECT");
        if (result.TikTokChecks.Any(x => x.TlsValid)) Add(_weights.TlsValid, "TLS valid");
        if (result.TikTokChecks.Any(x => x.TotalTime.TotalMilliseconds < _weights.LowLatencyMilliseconds)) Add(_weights.LowLatency, "Low latency");
        var independentFamilies = result.Endpoint.SourceFamilies.Count > 0 ? result.Endpoint.SourceFamilies.Count : result.Endpoint.Sources.Count;
        if (independentFamilies > 1) Add(Math.Min(_weights.MultipleSourcesMax, independentFamilies - 1), "Multiple source families");
        if (result.SuccessfulChecks > 1) Add(_weights.SecondSuccess, "Repeated success");
        if (result.TikTokChecks.Any(x => x.Status == TikTokStatus.CaptchaOrChallenge)
            || result.TikTokCapabilities.Any(x => x.Status == TikTokCapabilityStatus.Challenge)) Add(-_weights.ChallengePenalty, "Challenge/CAPTCHA");

        if (result.ExitIp?.Status == ExitIpStatus.Resolved) Add(_weights.ValidExitIp, "Valid exit IP");
        if (result.ExitIp is { Status: ExitIpStatus.Resolved, IsTransparentOrIneffective: false }) Add(_weights.ExitIpDifferent, "Exit IP differs from direct IP");
        if (result.Geo?.CountryCode is { } country && _preferredCountries.Contains(country)) Add(_weights.PreferredCountry, "Preferred country");
        AddCapability(TikTokCapability.TikTokHomepage, _weights.HomepagePassed, "Homepage passed");
        AddCapability(TikTokCapability.TikTokMobilePage, _mobileOptions?.ScoreBonus ?? _weights.MobilePagePassed, "Mobile page passed (optional)");
        if (_mobileOptions is { FailurePenalty: > 0 } && result.TikTokCapabilities.Any(x => x.Capability == TikTokCapability.TikTokMobilePage
            && x.Status is TikTokCapabilityStatus.Failed or TikTokCapabilityStatus.InvalidContent))
            Add(-_mobileOptions.FailurePenalty, "Mobile page failure (optional)");
        if (!result.TikTokCapabilities.Any(x => x.Capability == TikTokCapability.TikTokPostPage && x.Status == TikTokCapabilityStatus.Passed))
            AddCapability(TikTokCapability.TikTokPublicVideoPage, _weights.VideoPagePassed, "Video page passed");
        AddCapability(TikTokCapability.TikTokPostPage, _weights.VideoPagePassed, "Post page passed");
        AddCapability(TikTokCapability.TikTokOEmbed, _weights.OEmbedPassed, "oEmbed passed");
        if (result.BrowserPlayback.OriginalPostPlaybackResult?.Status == BrowserVerificationStatus.Passed
            || result.BrowserPlayback.EmbedPlayerPlaybackResult?.Status == BrowserVerificationStatus.Passed
            || result.BrowserVerification?.Status == BrowserVerificationStatus.Passed)
            Add(_weights.BrowserPlaybackPassed, "Browser playback passed");
        var effectiveStability = result.TikTokPageStability ?? result.Stability;
        if (effectiveStability?.Status == ProxyStabilityStatus.Stable) Add(_weights.StabilityPassed, "Stability passed");
        if (effectiveStability?.StableExitIp == true) Add(_weights.StableExitIp, "Stable exit IP");
        if (effectiveStability is { MedianLatencyMs: > 0 } stability)
        {
            if (stability.MedianLatencyMs < _weights.LowLatencyMilliseconds) Add(_weights.LowLatency, "Stage 2 low latency");
            else if (stability.MedianLatencyMs < _weights.MediumLatencyMilliseconds) Add(_weights.MediumLatency, "Stage 2 medium latency");
        }
        if (_geoOptions is not null)
        {
            if (result.Geo?.Decision == GeoResolutionDecision.Unknown) Add(-_geoOptions.UnknownCountryScorePenalty, "Unknown geo");
            if (result.Geo?.Decision == GeoResolutionDecision.Conflicting) Add(-_geoOptions.ConflictingCountryScorePenalty, "Conflicting geo");
        }
        return new ProxyScore(Math.Clamp(score, 0, 100), reasons);

        void Add(int value, string reason) { score += value; reasons.Add($"{reason}: {value:+#;-#;0}"); }
        void AddCapability(TikTokCapability capability, int value, string reason)
        { if (result.TikTokCapabilities.Any(x => x.Capability == capability && x.Status == TikTokCapabilityStatus.Passed)) Add(value, reason); }
    }
}

public static class SensitiveData
{
    public static string RedactProxyUri(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.UserInfo)) return value;
        return $"{uri.Scheme}://***:***@{uri.Host}:{uri.Port}";
    }
}
