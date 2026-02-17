using System.Diagnostics;

namespace Krutaka.Telegram;

/// <summary>
/// Utility class for acquiring and releasing a file-based lock to prevent
/// multiple bot instances from polling the same Telegram bot token simultaneously.
/// </summary>
public sealed class PollingLockFile : IDisposable
{
    private readonly string _lockFilePath;
    private FileStream? _lockFileStream;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="PollingLockFile"/> class.
    /// </summary>
    /// <param name="lockFilePath">The path to the lock file. Defaults to {UserProfile}/.krutaka/.polling.lock if not specified.</param>
    public PollingLockFile(string? lockFilePath = null)
    {
        if (string.IsNullOrWhiteSpace(lockFilePath))
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var krutakaDir = Path.Combine(userProfile, ".krutaka");
            Directory.CreateDirectory(krutakaDir);
            _lockFilePath = Path.Combine(krutakaDir, ".polling.lock");
        }
        else
        {
            _lockFilePath = lockFilePath;
        }
    }

    /// <summary>
    /// Attempts to acquire the polling lock.
    /// </summary>
    /// <returns>True if the lock was acquired successfully; false if another process holds the lock.</returns>
    public bool TryAcquire()
    {
        if (_lockFileStream is not null)
        {
            return true; // Already acquired
        }

        try
        {
            // Try to create and acquire exclusive lock on the file
            _lockFileStream = new FileStream(
                _lockFilePath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None, // Exclusive lock - no other process can open
                bufferSize: 4096,
                FileOptions.DeleteOnClose);

            // Write current process ID to the lock file
            using var writer = new StreamWriter(_lockFileStream, leaveOpen: true);
            writer.WriteLine($"PID: {Environment.ProcessId}");
            writer.WriteLine($"Acquired: {DateTimeOffset.UtcNow:O}");
            writer.Flush();

            return true;
        }
        catch (IOException)
        {
            // Lock is held by another process
            _lockFileStream?.Dispose();
            _lockFileStream = null;
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            // Permission denied
            _lockFileStream?.Dispose();
            _lockFileStream = null;
            return false;
        }
    }

    /// <summary>
    /// Releases the polling lock.
    /// </summary>
    public void Release()
    {
        if (_lockFileStream is not null)
        {
            _lockFileStream.Dispose();
            _lockFileStream = null;
        }
    }

    /// <summary>
    /// Disposes the lock file, releasing the lock if held.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Release();
        _disposed = true;
    }
}
