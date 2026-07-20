using Microsoft.Extensions.Logging;

namespace TikTokProxyHunter.App;

public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly StreamWriter _writer;
    private readonly object _gate = new();

    public FileLoggerProvider(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        _writer = new StreamWriter(File.Open(path, FileMode.Append, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(categoryName, _writer, _gate);
    public void Dispose() => _writer.Dispose();

    private sealed class FileLogger(string category, StreamWriter writer, object gate) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Debug;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (gate)
            {
                writer.Write(DateTimeOffset.UtcNow.ToString("O"));
                writer.Write(" ["); writer.Write(logLevel); writer.Write("] "); writer.Write(category); writer.Write(": ");
                writer.WriteLine(formatter(state, exception));
                if (exception is not null) writer.WriteLine(exception);
            }
        }
    }
}
