using Krutaka.Core;

namespace Krutaka.Memory;

/// <summary>
/// Service for managing daily interaction logs.
/// Appends timestamped entries to date-based log files and indexes them for search.
/// </summary>
public sealed class DailyLogService : IDisposable
{
    private readonly string _logsDirectory;
    private readonly IMemoryService _memoryService;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="DailyLogService"/> class.
    /// </summary>
    /// <param name="logsDirectory">The directory where daily log files are stored.</param>
    /// <param name="memoryService">The memory service for indexing log entries.</param>
    public DailyLogService(string logsDirectory, IMemoryService memoryService)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(logsDirectory, nameof(logsDirectory));
        ArgumentNullException.ThrowIfNull(memoryService, nameof(memoryService));

        _logsDirectory = logsDirectory;
        _memoryService = memoryService;
    }

    /// <summary>
    /// Appends a timestamped entry to today's daily log file and indexes it for search.
    /// </summary>
    /// <param name="content">The content to log.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of chunks created during indexing.</returns>
    public async Task<int> AppendEntryAsync(string content, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentException.ThrowIfNullOrWhiteSpace(content, nameof(content));

        await _fileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Ensure logs directory exists
            if (!Directory.Exists(_logsDirectory))
            {
                Directory.CreateDirectory(_logsDirectory);
            }

            // Get today's log file path
            var today = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
            var logFilePath = Path.Combine(_logsDirectory, $"{today}.md");

            // Create timestamped entry
            var timestamp = DateTimeOffset.UtcNow.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
            var entry = $"**[{timestamp}]** {content}\n\n";

            // Append to log file
            await File.AppendAllTextAsync(logFilePath, entry, cancellationToken).ConfigureAwait(false);

            // Chunk and index the entry for search
            var source = $"daily-log/{today}";
            var chunksCreated = await _memoryService.ChunkAndIndexAsync(content, source, cancellationToken).ConfigureAwait(false);

            return chunksCreated;
        }
        finally
        {
            _fileLock.Release();
        }
    }

    /// <summary>
    /// Gets the path to today's daily log file.
    /// </summary>
    /// <returns>The full path to today's log file.</returns>
    public string GetTodaysLogPath()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var today = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        return Path.Combine(_logsDirectory, $"{today}.md");
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _fileLock.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
