using Microsoft.Extensions.Logging;

namespace TikTokProxyHunter.Desktop.Services;

public sealed record DesktopLogEntry(DateTimeOffset Timestamp, LogLevel Level, string Category, string Message);

public sealed class DesktopLogStore(int capacity = 2_000) : ILoggerProvider
{
    private readonly int _capacity = Math.Max(1, capacity); private readonly Queue<DesktopLogEntry> _entries = new(); private readonly object _gate = new();
    public event EventHandler? Changed;
    public IReadOnlyList<DesktopLogEntry> Snapshot(LogLevel minimum = LogLevel.Information)
    { lock (_gate) return _entries.Where(x => x.Level >= minimum).ToArray(); }
    public ILogger CreateLogger(string categoryName) => new StoreLogger(this, categoryName);
    public void Dispose() { }
    private void Add(DesktopLogEntry entry)
    { lock (_gate) { _entries.Enqueue(entry); while (_entries.Count > _capacity) _entries.Dequeue(); } Changed?.Invoke(this, EventArgs.Empty); }
    private sealed class StoreLogger(DesktopLogStore owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Debug;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return; var message = formatter(state, exception);
            if (exception is not null) message += $" [{exception.GetType().Name}: {exception.Message}]";
            message = TikTokProxyHunter.Core.SensitiveData.RedactProxyUri(message);
            owner.Add(new(DateTimeOffset.UtcNow, logLevel, category, message.Length > 2_000 ? message[..2_000] : message));
        }
    }
}
