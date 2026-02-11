using FluentAssertions;
using Krutaka.Core;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

public sealed class DailyLogServiceTests : IDisposable
{
    private readonly string _testRoot;
    private readonly string _logsDirectory;
    private readonly SqliteMemoryStore _memoryService;
    private readonly DailyLogService _service;

    public DailyLogServiceTests()
    {
        // Use a unique directory for each test run
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        _testRoot = Path.Combine(Path.GetTempPath(), $"krutaka-dailylog-test-{uniqueId}");
        _logsDirectory = Path.Combine(_testRoot, "logs");

        // Create file-based SQLite database for testing (in-memory doesn't work well with FTS5)
        var dbPath = Path.Combine(_testRoot, "test.db");
        var options = new MemoryOptions
        {
            DatabasePath = dbPath,
            ChunkSizeTokens = 500,
            ChunkOverlapTokens = 50
        };
        _memoryService = new SqliteMemoryStore(options);
        _memoryService.InitializeAsync().GetAwaiter().GetResult();

        _service = new DailyLogService(_logsDirectory, _memoryService);
    }

    public void Dispose()
    {
        _service.Dispose();
        _memoryService.Dispose();

        // Force garbage collection to release any remaining SQLite connections
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // Cleanup test directory with retry logic for file locks
        if (Directory.Exists(_testRoot))
        {
            TryDeleteDirectory(_testRoot);
        }

        GC.SuppressFinalize(this);
    }

    private static void TryDeleteDirectory(string path, int maxRetries = 3)
    {
        for (int i = 0; i < maxRetries; i++)
        {
            try
            {
                Directory.Delete(path, true);
                return;
            }
            catch (IOException) when (i < maxRetries - 1)
            {
                // Wait a bit before retrying
                Thread.Sleep(100);
            }
        }
    }

    [Fact]
    public async Task Should_CreateLogsDirectory_WhenItDoesNotExist()
    {
        // Act
        await _service.AppendEntryAsync("Test entry");

        // Assert
        Directory.Exists(_logsDirectory).Should().BeTrue();
    }

    [Fact]
    public async Task Should_CreateDailyLogFile_WithCorrectName()
    {
        // Act
        await _service.AppendEntryAsync("Test entry");

        // Assert
        var today = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        var expectedFile = Path.Combine(_logsDirectory, $"{today}.md");
        File.Exists(expectedFile).Should().BeTrue();
    }

    [Fact]
    public async Task Should_AppendTimestampedEntry()
    {
        // Act
        await _service.AppendEntryAsync("First interaction");

        // Assert
        var logPath = _service.GetTodaysLogPath();
        var content = await File.ReadAllTextAsync(logPath);
        content.Should().Contain("**[");
        content.Should().Contain("]** First interaction");
    }

    [Fact]
    public async Task Should_AppendMultipleEntries()
    {
        // Act
        await _service.AppendEntryAsync("Entry 1");
        await _service.AppendEntryAsync("Entry 2");
        await _service.AppendEntryAsync("Entry 3");

        // Assert
        var logPath = _service.GetTodaysLogPath();
        var content = await File.ReadAllTextAsync(logPath);
        content.Should().Contain("Entry 1");
        content.Should().Contain("Entry 2");
        content.Should().Contain("Entry 3");
    }

    [Fact]
    public async Task Should_IndexEntryIntoMemoryStore()
    {
        // Act
        var chunksCreated = await _service.AppendEntryAsync("Important technical decision: use SQLite for storage");

        // Assert
        chunksCreated.Should().BeGreaterThanOrEqualTo(0);

        // Verify the entry can be searched (use single keyword for better match)
        var results = await _memoryService.HybridSearchAsync("SQLite", topK: 10);
        results.Should().NotBeEmpty();
        results.Should().Contain(r => r.Content.Contains("SQLite", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Should_GetTodaysLogPath_WithCorrectFormat()
    {
        // Act
        var path = _service.GetTodaysLogPath();

        // Assert
        var today = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        path.Should().EndWith($"{today}.md");
        path.Should().StartWith(_logsDirectory);
    }

    [Fact]
    public async Task Should_ThrowArgumentException_WhenContentIsEmpty()
    {
        // Act
        var act = async () => await _service.AppendEntryAsync("");

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowArgumentException_WhenLogsDirectoryIsEmpty()
    {
        // Act
        var act = () => new DailyLogService("", _memoryService);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowArgumentNullException_WhenMemoryServiceIsNull()
    {
        // Act
        var act = () => new DailyLogService(_logsDirectory, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task Should_FormatTimestamp_Correctly()
    {
        // Act
        await _service.AppendEntryAsync("Test entry");

        // Assert
        var logPath = _service.GetTodaysLogPath();
        var content = await File.ReadAllTextAsync(logPath);

        // Verify timestamp format (HH:mm:ss)
        content.Should().MatchRegex(@"\*\*\[\d{2}:\d{2}:\d{2}\]\*\*");
    }
}
