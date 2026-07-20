using System.Collections.ObjectModel;
using TikTokProxyHunter.Core;
using TikTokProxyHunter.Desktop.Models;

namespace TikTokProxyHunter.Desktop.Services;

public sealed class PipelineProgressAggregator
{
    private readonly Dictionary<HunterUiStage, PipelineStageItem> _stages = Enum.GetValues<HunterUiStage>()
        .Where(x => x != HunterUiStage.Preparing).ToDictionary(x => x, x => new PipelineStageItem { Stage = x });
    public IReadOnlyList<PipelineStageItem> Stages => _stages.Values.OrderBy(x => x.Stage).ToArray();
    public UiRunState State { get; private set; } = new();
    public void Reset()
    {
        foreach (var stage in _stages.Keys.ToArray()) _stages[stage] = new PipelineStageItem { Stage = stage };
        State = new();
    }

    public void Apply(HunterRunProgress progress)
    {
        State = State with { Status = progress.Status, RunId = progress.RunId,
            StartedAt = State.StartedAt ?? progress.Timestamp, CurrentStage = progress.Stage?.Stage,
            StatusText = progress.Message ?? StatusText.RunStatus(progress.Status) };
        if (progress.Stage is not { } stage) return;
        if (progress.Event == HunterProgressEvent.StageStarted)
            foreach (var prior in _stages.Where(x => x.Key != stage.Stage && x.Value.Status == HunterStageStatus.Running).Select(x => x.Key).ToArray())
                _stages[prior] = _stages[prior] with { Status = HunterStageStatus.CompletedWithWarnings };
        _stages[stage.Stage] = new PipelineStageItem { Stage = stage.Stage, Status = stage.Status,
            Processed = stage.Processed, Total = stage.Total, Passed = stage.Passed, Rejected = stage.Rejected,
            ItemsPerSecond = stage.ItemsPerSecond };
        State = stage.Stage switch
        {
            HunterUiStage.Normalizing => State with { Collected = stage.Processed, Unique = stage.Passed },
            HunterUiStage.ProbingProtocols => State with { ProtocolAlive = stage.Passed },
            HunterUiStage.CheckingHttps => State with { GenericHttps = stage.Passed },
            HunterUiStage.CheckingTikTok => State with { TikTokAccessible = stage.Passed },
            HunterUiStage.CheckingStability => State with { Stable = stage.Passed },
            _ => State
        };
    }
}

public sealed class PipelineUiAdapter(IUiDispatcher dispatcher) : IHunterRunObserver
{
    private readonly PipelineProgressAggregator _aggregator = new();
    public event EventHandler? Changed;
    public UiRunState State => _aggregator.State;
    public IReadOnlyList<PipelineStageItem> Stages => _aggregator.Stages;
    public void Reset() { dispatcher.Post(() => { _aggregator.Reset(); Changed?.Invoke(this, EventArgs.Empty); }); }
    public ValueTask OnProgressAsync(HunterRunProgress progress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        dispatcher.Post(() => { _aggregator.Apply(progress); Changed?.Invoke(this, EventArgs.Empty); });
        return ValueTask.CompletedTask;
    }
}

public sealed class BoundedLogBuffer(int capacity = 2_000)
{
    private readonly int _capacity = Math.Max(1, capacity); private readonly Queue<string> _items = new(); private readonly object _gate = new();
    public IReadOnlyList<string> Snapshot() { lock (_gate) return _items.ToArray(); }
    public void Add(string line)
    {
        lock (_gate) { _items.Enqueue(line); while (_items.Count > _capacity) _items.Dequeue(); }
    }
}
