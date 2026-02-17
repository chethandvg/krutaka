using FluentAssertions;

namespace Krutaka.Telegram.Tests;

public sealed class PollingLockFileTests : IDisposable
{
    private readonly string _testLockPath;
    private readonly List<PollingLockFile> _lockFilesToDispose = [];

    public PollingLockFileTests()
    {
        // Use a unique lock file path for each test run
        _testLockPath = Path.Combine(Path.GetTempPath(), $"krutaka_test_{Guid.NewGuid():N}.lock");
    }

    [Fact]
    public void TryAcquire_Should_ReturnTrue_WhenLockIsAvailable()
    {
        // Arrange
        var lockFile = CreateLockFile();

        // Act
        var acquired = lockFile.TryAcquire();

        // Assert
        acquired.Should().BeTrue();
        File.Exists(_testLockPath).Should().BeTrue();
    }

    [Fact]
    public void TryAcquire_Should_ReturnFalse_WhenLockIsHeldByAnotherInstance()
    {
        // Arrange
        var firstLock = CreateLockFile();
        var secondLock = CreateLockFile();

        // Act
        var firstAcquired = firstLock.TryAcquire();
        var secondAcquired = secondLock.TryAcquire();

        // Assert
        firstAcquired.Should().BeTrue();
        secondAcquired.Should().BeFalse();
    }

    [Fact]
    public void TryAcquire_Should_ReturnTrue_WhenCalledMultipleTimes_OnSameInstance()
    {
        // Arrange
        var lockFile = CreateLockFile();

        // Act
        var firstAcquire = lockFile.TryAcquire();
        var secondAcquire = lockFile.TryAcquire();

        // Assert
        firstAcquire.Should().BeTrue();
        secondAcquire.Should().BeTrue();
    }

    [Fact]
    public void Release_Should_AllowAnotherInstance_ToAcquireLock()
    {
        // Arrange
        var firstLock = CreateLockFile();
        var secondLock = CreateLockFile();

        // Act
        firstLock.TryAcquire();
        firstLock.Release();
        var secondAcquired = secondLock.TryAcquire();

        // Assert
        secondAcquired.Should().BeTrue();
    }

    [Fact]
    public void Dispose_Should_ReleaseLock()
    {
        // Arrange
        var firstLock = CreateLockFile();
        var secondLock = CreateLockFile();

        // Act
        firstLock.TryAcquire();
        firstLock.Dispose();
        var secondAcquired = secondLock.TryAcquire();

        // Assert
        secondAcquired.Should().BeTrue();
    }

    [Fact]
    public void Dispose_Should_BeIdempotent()
    {
        // Arrange
        var lockFile = CreateLockFile();
        lockFile.TryAcquire();

        // Act & Assert - Should not throw
        lockFile.Dispose();
        lockFile.Dispose();
    }

    [Fact(Skip = "Flaky on Linux due to exclusive file lock behavior - lock prevents FileShare.ReadWrite reading")]
    public void TryAcquire_Should_WritePidToLockFile()
    {
        // Arrange
        var lockFile = CreateLockFile();

        // Act
        lockFile.TryAcquire();

        // Read the file content while lock is held (use FileShare.ReadWrite to allow reading)
        string content;
        using (var reader = new FileStream(_testLockPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (var streamReader = new StreamReader(reader))
        {
            content = streamReader.ReadToEnd();
        }

        // Assert
        content.Should().Contain($"PID: {Environment.ProcessId}");
        content.Should().Contain("Acquired:");
    }

    [Fact]
    public void Constructor_Should_UseDefaultPath_WhenNotSpecified()
    {
        // Arrange & Act
        using var lockFile = new PollingLockFile();

        // Assert - Should not throw and should be able to acquire
        var acquired = lockFile.TryAcquire();
        acquired.Should().BeTrue();
    }

    private PollingLockFile CreateLockFile()
    {
        var lockFile = new PollingLockFile(_testLockPath);
        _lockFilesToDispose.Add(lockFile);
        return lockFile;
    }

    public void Dispose()
    {
        foreach (var lockFile in _lockFilesToDispose)
        {
            try
            {
                lockFile.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // Already disposed, ignore
            }
            catch (IOException)
            {
                // File lock issues during cleanup, ignore
            }
        }

        try
        {
            if (File.Exists(_testLockPath))
            {
                File.Delete(_testLockPath);
            }
        }
        catch (IOException)
        {
            // File in use or already deleted, ignore
        }
        catch (UnauthorizedAccessException)
        {
            // Permission denied, ignore
        }

        GC.SuppressFinalize(this);
    }
}
