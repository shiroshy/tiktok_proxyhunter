using TikTokProxyHunter.Core;

namespace TikTokProxyHunter.Desktop.Models;

public sealed class DesktopSession
{
    public HunterRunResult? LastRun { get; private set; }
    public string? LastOutputDirectory => LastRun?.Summary.OutputDirectory;
    public event EventHandler? Changed;
    public void SetRun(HunterRunResult result) { LastRun = result; Changed?.Invoke(this, EventArgs.Empty); }
}

public sealed record NavigationItem(string Key, string Title, string Glyph, string ToolTip);
