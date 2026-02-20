namespace Krutaka.Core;

/// <summary>
/// Tracks resource consumption for an agentic task against a <see cref="TaskBudget"/>.
/// Implementations are responsible for maintaining thread-safe counters for each
/// <see cref="BudgetDimension"/> and signalling exhaustion when any limit is reached.
/// </summary>
public interface ITaskBudgetTracker
{
    /// <summary>
    /// Attempts to consume the specified amount from the given budget dimension.
    /// </summary>
    /// <param name="dimension">The resource dimension to consume from.</param>
    /// <param name="amount">The amount to consume. Must be greater than zero.</param>
    /// <returns>
    /// <see langword="true"/> if the amount was successfully consumed without exceeding the limit;
    /// <see langword="false"/> if consuming would exceed (or already has exceeded) the limit.
    /// </returns>
    bool TryConsume(BudgetDimension dimension, int amount);

    /// <summary>
    /// Returns an immutable snapshot of the current resource consumption.
    /// </summary>
    /// <returns>A <see cref="TaskBudgetSnapshot"/> reflecting consumption at the moment of the call.</returns>
    TaskBudgetSnapshot GetSnapshot();

    /// <summary>
    /// Gets a value indicating whether any budget dimension has reached or exceeded its limit.
    /// </summary>
    bool IsExhausted { get; }
}
