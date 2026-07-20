using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TikTokProxyHunter.Desktop.Models;

namespace TikTokProxyHunter.Desktop.ViewModels;

public sealed partial class QuickScanViewModel : ObservableObject
{
    public QuickScanViewModel(UiRunConfiguration initial)
    {
        Preset = initial.Preset; CustomLimit = initial.MaximumCandidates; CheckPublicVideo = initial.CheckPublicVideo;
        PublicVideoUrl = initial.PublicVideoUrl; BrowserVerification = initial.BrowserVerification; AllowUnknownGeo = initial.AllowUnknownGeo;
        ApplyPreset(); Validate();
    }
    [ObservableProperty] private ScanPreset preset;
    [ObservableProperty] private int customLimit = 3_000;
    [ObservableProperty] private bool checkPublicVideo;
    [ObservableProperty] private string publicVideoUrl = string.Empty;
    [ObservableProperty] private bool browserVerification;
    [ObservableProperty] private bool allowUnknownGeo = true;
    [ObservableProperty] private string validationMessage = string.Empty;
    public IReadOnlyList<ScanPreset> Presets { get; } = Enum.GetValues<ScanPreset>();
    public UiRunConfiguration Configuration => new() { Preset = Preset, MaximumCandidates = CustomLimit,
        CheckPublicVideo = CheckPublicVideo, PublicVideoUrl = PublicVideoUrl, BrowserVerification = BrowserVerification,
        AllowUnknownGeo = AllowUnknownGeo };
    public bool IsValid => Configuration.Validate().Count == 0;
    partial void OnPresetChanged(ScanPreset value) { ApplyPreset(); Validate(); }
    partial void OnCustomLimitChanged(int value) => Validate();
    partial void OnCheckPublicVideoChanged(bool value) { if (!value) BrowserVerification = false; Validate(); }
    partial void OnPublicVideoUrlChanged(string value) => Validate();
    partial void OnBrowserVerificationChanged(bool value) => Validate();
    private void ApplyPreset() => CustomLimit = Preset switch { ScanPreset.Quick => 1_000, ScanPreset.Normal => 3_000, ScanPreset.Deep => 10_000, _ => CustomLimit };
    private void Validate() { var errors = Configuration.Validate(); ValidationMessage = string.Join(Environment.NewLine, errors); OnPropertyChanged(nameof(IsValid)); }
}
