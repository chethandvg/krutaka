namespace Krutaka.Telegram;

/// <summary>
/// Thread-safe sliding window counter for rate limiting.
/// Tracks command timestamps and removes expired entries.
/// </summary>
internal sealed class SlidingWindowCounter
{
    private readonly List<long> _timestamps = [];
    private readonly object _lock = new();

    /// <summary>
    /// Adds a new timestamp to the window and returns the count within the window.
    /// Automatically removes expired timestamps.
    /// </summary>
    /// <param name="currentTicks">The current tick count in milliseconds (from Environment.TickCount64).</param>
    /// <param name="windowDurationTicks">The window duration in milliseconds.</param>
    /// <returns>The number of timestamps within the window (including the new one).</returns>
    public int AddAndGetCount(long currentTicks, long windowDurationTicks)
    {
        lock (_lock)
        {
            // Remove expired timestamps
            _timestamps.RemoveAll(ts => currentTicks - ts > windowDurationTicks);

            // Add current timestamp
            _timestamps.Add(currentTicks);

            return _timestamps.Count;
        }
    }

    /// <summary>
    /// Gets the current count of timestamps within the window without adding a new one.
    /// Automatically removes expired timestamps.
    /// </summary>
    /// <param name="currentTicks">The current tick count in milliseconds (from Environment.TickCount64).</param>
    /// <param name="windowDurationTicks">The window duration in milliseconds.</param>
    /// <returns>The number of timestamps within the window.</returns>
    public int GetCount(long currentTicks, long windowDurationTicks)
    {
        lock (_lock)
        {
            // Remove expired timestamps
            _timestamps.RemoveAll(ts => currentTicks - ts > windowDurationTicks);

            return _timestamps.Count;
        }
    }
}
