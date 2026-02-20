namespace Krutaka.Core;

public sealed partial class AgentOrchestrator
{
    /// <summary>
    /// Blocks asynchronously until the agent transitions out of <see cref="AgentState.Paused"/>.
    /// Returns immediately if the agent is not currently paused.
    /// Does NOT yield events; event emission is the caller's responsibility to preserve correct ordering.
    /// </summary>
    private async Task WaitWhilePausedAsync(CancellationToken cancellationToken)
    {
        while (_stateManager!.CurrentState == AgentState.Paused)
        {
            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }
    }
}
