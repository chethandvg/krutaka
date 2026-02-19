using System.Collections.Concurrent;

namespace Krutaka.Telegram;

/// <summary>
/// Rate limiting partial for TelegramResponseStreamer.
/// </summary>
public sealed partial class TelegramResponseStreamer
{
    // Shared per-chat rate limiters to enforce Telegram's 30 edits/min/chat across all concurrent sessions
    private static readonly ConcurrentDictionary<long, RateLimitTracker> _perChatRateLimiters = new();

    /// <summary>
    /// Tracks edit operations to enforce Telegram's rate limit of ~30 edits/minute/chat.
    /// Uses monotonic clock (Environment.TickCount64) for reliability.
    /// Shared across all StreamResponseAsync calls for the same chat ID.
    /// </summary>
    private sealed class RateLimitTracker : IDisposable
    {
        private readonly int _maxEdits;
        private readonly long _windowTicks;
        private readonly Queue<long> _editTimestamps = new();
        private readonly SemaphoreSlim _semaphore = new(1, 1);
        private bool _disposed;

        public RateLimitTracker(int maxEdits, int windowMs)
        {
            _maxEdits = maxEdits;
            // Convert milliseconds to ticks (Environment.TickCount64 is in milliseconds)
            _windowTicks = windowMs;
        }

        public void RecordEdit()
        {
            _editTimestamps.Enqueue(Environment.TickCount64);
        }

        public async Task WaitIfNeededAsync(CancellationToken cancellationToken)
        {
            await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // Remove old timestamps outside the window
                var cutoff = Environment.TickCount64 - _windowTicks;
                while (_editTimestamps.Count > 0 && _editTimestamps.Peek() < cutoff)
                {
                    _editTimestamps.Dequeue();
                }

                // If we're at the limit, wait until the oldest edit expires
                if (_editTimestamps.Count >= _maxEdits)
                {
                    var oldestEdit = _editTimestamps.Peek();
                    var waitTicks = oldestEdit + _windowTicks - Environment.TickCount64;

                    if (waitTicks > 0)
                    {
                        await Task.Delay((int)waitTicks, cancellationToken).ConfigureAwait(false);

                        // Remove the expired edit
                        _editTimestamps.Dequeue();
                    }
                }
            }
            finally
            {
                _semaphore.Release();
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _semaphore.Dispose();
            _disposed = true;
        }
    }
}
