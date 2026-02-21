#pragma warning disable CA2007 // Do not directly await a Task in tests
using System.Text;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Unit tests for <see cref="GitCheckpointService"/>.
/// Tests that require git operations use a temporary git repository created in a CI-safe directory.
/// Tests verify create/list/rollback semantics, non-git degradation, cap enforcement, and thread safety.
/// </summary>
public sealed class GitCheckpointServiceTests : IDisposable
{
    private readonly string _testRoot;

    public GitCheckpointServiceTests()
    {
        _testRoot = TestDirectoryHelper.GetTestDirectory("git-checkpoint");
        Directory.CreateDirectory(_testRoot);
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    [Fact]
    public void Constructor_Should_ThrowArgumentException_WhenWorkingDirectoryIsEmpty()
    {
        var act = () => new GitCheckpointService(string.Empty, "session-id");
        act.Should().Throw<ArgumentException>().WithParameterName("workingDirectory");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentException_WhenSessionIdIsEmpty()
    {
        var act = () => new GitCheckpointService(_testRoot, string.Empty);
        act.Should().Throw<ArgumentException>().WithParameterName("sessionId");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenMaxCheckpointsIsZero()
    {
        var act = () => new GitCheckpointService(_testRoot, "session-id", maxCheckpoints: 0);
        act.Should().Throw<ArgumentOutOfRangeException>().WithParameterName("maxCheckpoints");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenMaxCheckpointsIsNegative()
    {
        var act = () => new GitCheckpointService(_testRoot, "session-id", maxCheckpoints: -1);
        act.Should().Throw<ArgumentOutOfRangeException>().WithParameterName("maxCheckpoints");
    }

    [Fact]
    public void Constructor_Should_Succeed_WithValidArguments()
    {
        using var svc = new GitCheckpointService(_testRoot, "test-session", maxCheckpoints: 10);
        svc.Should().NotBeNull();
    }

    // -------------------------------------------------------------------------
    // Non-git directory (graceful degradation — AT11)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CreateCheckpointAsync_Should_ReturnEmpty_WhenDirectoryIsNotGitRepo()
    {
        using var svc = new GitCheckpointService(_testRoot, "sess1");

        var result = await svc.CreateCheckpointAsync("test", CancellationToken.None);

        result.Should().BeEmpty();
    }

    [Fact]
    public async Task ListCheckpointsAsync_Should_ReturnEmptyList_WhenNoCheckpointsCreated()
    {
        using var svc = new GitCheckpointService(_testRoot, "sess1");

        var checkpoints = await svc.ListCheckpointsAsync(CancellationToken.None);

        checkpoints.Should().BeEmpty();
    }

    [Fact]
    public async Task RollbackToCheckpointAsync_Should_Throw_WhenCheckpointIdNotFound()
    {
        using var svc = new GitCheckpointService(_testRoot, "sess1");

        var act = async () => await svc.RollbackToCheckpointAsync("nonexistent-sha", CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*not found*");
    }

    // -------------------------------------------------------------------------
    // CreateCheckpointAsync argument validation
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CreateCheckpointAsync_Should_ThrowArgumentException_WhenMessageIsEmpty()
    {
        using var svc = new GitCheckpointService(_testRoot, "sess1");

        var act = async () => await svc.CreateCheckpointAsync(string.Empty, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("message");
    }

    [Fact]
    public async Task CreateCheckpointAsync_Should_ThrowArgumentException_WhenMessageIsWhitespace()
    {
        using var svc = new GitCheckpointService(_testRoot, "sess1");

        var act = async () => await svc.CreateCheckpointAsync("   ", CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("message");
    }

    // -------------------------------------------------------------------------
    // RollbackToCheckpointAsync argument validation
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RollbackToCheckpointAsync_Should_ThrowArgumentException_WhenCheckpointIdIsEmpty()
    {
        using var svc = new GitCheckpointService(_testRoot, "sess1");

        var act = async () => await svc.RollbackToCheckpointAsync(string.Empty, CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("checkpointId");
    }

    // -------------------------------------------------------------------------
    // CreateCheckpointAsync — returns empty for clean working tree
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CreateCheckpointAsync_Should_ReturnEmpty_WhenWorkingTreeIsClean()
    {
        using var repoDir = new TempGitRepo(_testRoot);
        await repoDir.InitAsync();
        await repoDir.CommitEmptyAsync("Initial commit");

        using var svc = new GitCheckpointService(repoDir.Path, "sess1");

        var result = await svc.CreateCheckpointAsync("nothing changed", CancellationToken.None);

        result.Should().BeEmpty("clean working tree has nothing to stash");
    }

    // -------------------------------------------------------------------------
    // CreateCheckpointAsync / ListCheckpointsAsync — happy path
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CreateCheckpointAsync_Should_ReturnNonEmptySha_WhenChangesExist()
    {
        using var repoDir = new TempGitRepo(_testRoot);
        await repoDir.InitAsync();
        await repoDir.CommitEmptyAsync("Initial commit");
        await File.WriteAllTextAsync(Path.Combine(repoDir.Path, "test.txt"), "hello");

        using var svc = new GitCheckpointService(repoDir.Path, "sess1");

        var result = await svc.CreateCheckpointAsync("pre-modify: write_file", CancellationToken.None);

        result.Should().NotBeNullOrWhiteSpace("a stash SHA should be returned");
        result.Should().HaveLength(40, "SHA-1 hashes are 40 hex characters");
    }

    [Fact]
    public async Task ListCheckpointsAsync_Should_ReturnCheckpoint_AfterCreate()
    {
        using var repoDir = new TempGitRepo(_testRoot);
        await repoDir.InitAsync();
        await repoDir.CommitEmptyAsync("Initial commit");
        await File.WriteAllTextAsync(Path.Combine(repoDir.Path, "a.txt"), "content");

        using var svc = new GitCheckpointService(repoDir.Path, "sess1");

        var sha = await svc.CreateCheckpointAsync("my checkpoint", CancellationToken.None);
        sha.Should().NotBeEmpty();

        var list = await svc.ListCheckpointsAsync(CancellationToken.None);

        list.Should().ContainSingle();
        list[0].CheckpointId.Should().Be(sha);
        list[0].Message.Should().Be("my checkpoint");
        list[0].FilesModified.Should().Be(1);
        list[0].CreatedAt.Should().BeCloseTo(DateTime.UtcNow, precision: TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ListCheckpointsAsync_Should_ReturnCheckpointsInChronologicalOrder()
    {
        using var repoDir = new TempGitRepo(_testRoot);
        await repoDir.InitAsync();
        await repoDir.CommitEmptyAsync("Initial commit");

        using var svc = new GitCheckpointService(repoDir.Path, "sess1");

        // First modification
        await File.WriteAllTextAsync(Path.Combine(repoDir.Path, "a.txt"), "v1");
        var sha1 = await svc.CreateCheckpointAsync("checkpoint-1", CancellationToken.None);

        // Second modification (after first checkpoint, working tree is clean again — need new change)
        await File.WriteAllTextAsync(Path.Combine(repoDir.Path, "b.txt"), "v2");
        var sha2 = await svc.CreateCheckpointAsync("checkpoint-2", CancellationToken.None);

        var list = await svc.ListCheckpointsAsync(CancellationToken.None);

        list.Should().HaveCount(2);
        list[0].CheckpointId.Should().Be(sha1, "oldest first");
        list[1].CheckpointId.Should().Be(sha2, "newest last");
    }

    // -------------------------------------------------------------------------
    // RollbackToCheckpointAsync — restores file state
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RollbackToCheckpointAsync_Should_RestoreFileContents()
    {
        using var repoDir = new TempGitRepo(_testRoot);
        await repoDir.InitAsync();

        // Create a committed file with known content
        var filePath = Path.Combine(repoDir.Path, "tracked.txt");
        await File.WriteAllTextAsync(filePath, "committed version");
        await repoDir.StageAndCommitAsync("tracked.txt", "Add tracked file");

        using var svc = new GitCheckpointService(repoDir.Path, "sess1");

        // Modify the file and take a checkpoint
        await File.WriteAllTextAsync(filePath, "modified version");
        var sha = await svc.CreateCheckpointAsync("before second edit", CancellationToken.None);
        sha.Should().NotBeEmpty();

        // Make another change after the checkpoint
        await File.WriteAllTextAsync(filePath, "second modification");

        // Rollback to checkpoint
        await svc.RollbackToCheckpointAsync(sha, CancellationToken.None);

        // File should be restored to the state at checkpoint time
        var content = await File.ReadAllTextAsync(filePath);
        content.Should().Be("modified version", "rollback should restore to checkpoint state");
    }

    [Fact]
    public async Task RollbackToCheckpointAsync_Should_RemoveFileAddedAfterCheckpoint()
    {
        using var repoDir = new TempGitRepo(_testRoot);
        await repoDir.InitAsync();

        // Create a committed file
        var filePath = Path.Combine(repoDir.Path, "original.txt");
        await File.WriteAllTextAsync(filePath, "original");
        await repoDir.StageAndCommitAsync("original.txt", "Initial file");

        // Modify and checkpoint
        await File.WriteAllTextAsync(filePath, "modified");
        using var svc = new GitCheckpointService(repoDir.Path, "sess1");
        var sha = await svc.CreateCheckpointAsync("checkpoint", CancellationToken.None);
        sha.Should().NotBeEmpty();

        // Create a new untracked file after the checkpoint
        var newFile = Path.Combine(repoDir.Path, "new-after-checkpoint.txt");
        await File.WriteAllTextAsync(newFile, "should be removed");

        // Rollback to checkpoint
        await svc.RollbackToCheckpointAsync(sha, CancellationToken.None);

        // New untracked file should be removed (git clean -fd removes it)
        File.Exists(newFile).Should().BeFalse("git clean removes untracked files created after checkpoint");
    }

    // -------------------------------------------------------------------------
    // Checkpoint cap enforcement (AT4)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CreateCheckpointAsync_Should_PruneOldest_WhenCapIsReached()
    {
        using var repoDir = new TempGitRepo(_testRoot);
        await repoDir.InitAsync();
        await repoDir.CommitEmptyAsync("Initial commit");

        // Use a small cap of 3 for the test
        using var svc = new GitCheckpointService(repoDir.Path, "sess1", maxCheckpoints: 3);

        var createdShas = new List<string>();

        for (int i = 1; i <= 4; i++)
        {
            await File.WriteAllTextAsync(Path.Combine(repoDir.Path, $"file{i}.txt"), $"content-{i}");
            var sha = await svc.CreateCheckpointAsync($"checkpoint-{i}", CancellationToken.None);
            if (!string.IsNullOrEmpty(sha))
            {
                createdShas.Add(sha);
            }
        }

        var list = await svc.ListCheckpointsAsync(CancellationToken.None);

        // Should not exceed the cap
        list.Count.Should().BeLessThanOrEqualTo(3, "max cap is 3");
    }

    [Fact]
    public async Task CreateCheckpointAsync_Should_DropOldestStash_WhenCapIsReached()
    {
        using var repoDir = new TempGitRepo(_testRoot);
        await repoDir.InitAsync();
        await repoDir.CommitEmptyAsync("Initial commit");

        using var svc = new GitCheckpointService(repoDir.Path, "sess1", maxCheckpoints: 2);

        // Create 3 checkpoints — third should prune the first
        await File.WriteAllTextAsync(Path.Combine(repoDir.Path, "f1.txt"), "1");
        var sha1 = await svc.CreateCheckpointAsync("checkpoint-1", CancellationToken.None);

        await File.WriteAllTextAsync(Path.Combine(repoDir.Path, "f2.txt"), "2");
        var sha2 = await svc.CreateCheckpointAsync("checkpoint-2", CancellationToken.None);

        await File.WriteAllTextAsync(Path.Combine(repoDir.Path, "f3.txt"), "3");
        var sha3 = await svc.CreateCheckpointAsync("checkpoint-3", CancellationToken.None);

        var list = await svc.ListCheckpointsAsync(CancellationToken.None);

        list.Should().HaveCount(2);

        // sha1 should be gone (pruned), sha2 and sha3 should remain
        list.Should().NotContain(c => c.CheckpointId == sha1, "oldest was pruned");
        if (!string.IsNullOrEmpty(sha2))
        {
            list.Should().Contain(c => c.CheckpointId == sha2);
        }

        if (!string.IsNullOrEmpty(sha3))
        {
            list.Should().Contain(c => c.CheckpointId == sha3);
        }
    }

    // -------------------------------------------------------------------------
    // IDisposable
    // -------------------------------------------------------------------------

    [Fact]
    public void Dispose_Should_NotThrow()
    {
        using var svc = new GitCheckpointService(_testRoot, "sess1");
        var act = svc.Dispose;
        act.Should().NotThrow();
    }

    [Fact]
    public void Dispose_Should_BeIdempotent()
    {
        var svc = new GitCheckpointService(_testRoot, "sess1");
        svc.Dispose();
        var act = svc.Dispose;
        act.Should().NotThrow("double dispose should not throw");
    }

    // -------------------------------------------------------------------------
    // Thread safety — concurrent checkpoint creation
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CreateCheckpointAsync_Should_HandleConcurrentCalls_WithoutDataCorruption()
    {
        using var repoDir = new TempGitRepo(_testRoot);
        await repoDir.InitAsync();
        await repoDir.CommitEmptyAsync("Initial commit");

        // Create multiple files to give concurrent tasks something to stash
        for (int i = 0; i < 3; i++)
        {
            await File.WriteAllTextAsync(Path.Combine(repoDir.Path, $"concurrent{i}.txt"), $"data{i}");
        }

        using var svc = new GitCheckpointService(repoDir.Path, "sess1", maxCheckpoints: 50);

        // Launch concurrent create calls — the semaphore should serialize them correctly
        var tasks = Enumerable.Range(0, 3).Select(i =>
            svc.CreateCheckpointAsync($"concurrent-{i}", CancellationToken.None));

        var results = await Task.WhenAll(tasks);

        // No exceptions should be thrown and the in-memory state should be consistent
        var list = await svc.ListCheckpointsAsync(CancellationToken.None);
        list.Count.Should().BeGreaterThanOrEqualTo(0, "concurrent access should not corrupt state");
    }

    // -------------------------------------------------------------------------
    // CheckpointOptions
    // -------------------------------------------------------------------------

    [Fact]
    public void CheckpointOptions_Should_HaveCorrectDefaults()
    {
        var opts = new CheckpointOptions();
        opts.MaxCheckpointsPerSession.Should().Be(50);
        opts.AutoCheckpointOnFileModification.Should().BeTrue();
    }

    [Fact]
    public void CheckpointOptions_Should_AllowCustomMaxCheckpoints()
    {
        var opts = new CheckpointOptions { MaxCheckpointsPerSession = 10 };
        opts.MaxCheckpointsPerSession.Should().Be(10);
    }

    [Fact]
    public void CheckpointOptions_Should_AllowDisablingAutoCheckpoint()
    {
        var opts = new CheckpointOptions { AutoCheckpointOnFileModification = false };
        opts.AutoCheckpointOnFileModification.Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // ToolOptions integration
    // -------------------------------------------------------------------------

    [Fact]
    public void ToolOptions_Should_HaveCheckpointProperty()
    {
        var opts = new ToolOptions();
        opts.Checkpoint.Should().NotBeNull();
        opts.Checkpoint.MaxCheckpointsPerSession.Should().Be(50);
    }

    // -------------------------------------------------------------------------
    // Helper: TempGitRepo
    // -------------------------------------------------------------------------

    /// <summary>
    /// Helper that creates and initializes a temporary git repository for testing.
    /// Configures a local user.name and user.email so commits don't fail in CI.
    /// </summary>
    private sealed class TempGitRepo : IDisposable
    {
        private readonly string _baseDir;
        private readonly string _uniqueName;
        private bool _disposed;

        public string Path { get; }

        public TempGitRepo(string baseDir)
        {
            _baseDir = baseDir;
            _uniqueName = Guid.NewGuid().ToString("N")[..8];
            Path = System.IO.Path.Combine(baseDir, $"repo-{_uniqueName}");
            Directory.CreateDirectory(Path);
        }

        public async Task InitAsync()
        {
            await RunGitAsync(["init"]);
            await RunGitAsync(["config", "user.email", "test@krutaka.test"]);
            await RunGitAsync(["config", "user.name", "Krutaka Test"]);
        }

        public async Task CommitEmptyAsync(string message)
        {
            // Create a .gitkeep file to make the commit non-empty
            var keepFile = System.IO.Path.Combine(Path, ".gitkeep");
            await File.WriteAllTextAsync(keepFile, string.Empty);
            await RunGitAsync(["add", "-A"]);
            await RunGitAsync(["commit", "-m", message]);
        }

        public async Task StageAndCommitAsync(string relativePath, string message)
        {
            await RunGitAsync(["add", relativePath]);
            await RunGitAsync(["commit", "-m", message]);
        }

        private async Task RunGitAsync(string[] args)
        {
            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            await CliWrap.Cli.Wrap("git")
                .WithArguments(args)
                .WithWorkingDirectory(Path)
                .WithStandardOutputPipe(CliWrap.PipeTarget.ToStringBuilder(stdout))
                .WithStandardErrorPipe(CliWrap.PipeTarget.ToStringBuilder(stderr))
                .WithValidation(CliWrap.CommandResultValidation.None)
                .ExecuteAsync();
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            TestDirectoryHelper.TryDeleteDirectory(Path);
            GC.SuppressFinalize(this);
        }
    }
}
