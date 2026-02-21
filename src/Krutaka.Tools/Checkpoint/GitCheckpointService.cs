using System.Text;
using CliWrap;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Git-based checkpoint service that uses <c>git stash</c> to capture working-tree snapshots
/// before file modifications. Enables rollback to a prior state if agent actions are undesired.
/// </summary>
/// <remarks>
/// Security invariants:
/// <list type="bullet">
///   <item><description><b>S11</b>: No <c>git push</c> — all operations are local only.</description></item>
///   <item><description>AT4: Maximum checkpoint cap enforced; oldest checkpoint is pruned when the cap is reached.</description></item>
///   <item><description>AT11: Non-git directories are detected via <c>git rev-parse --git-dir</c> and handled gracefully — works for regular repos, worktrees, and repos with <c>--separate-git-dir</c>.</description></item>
/// </list>
/// Thread-safety: all public methods acquire a <see cref="SemaphoreSlim"/> before mutating state.
/// </remarks>
public sealed class GitCheckpointService : IGitCheckpointService, IDisposable
{
    private readonly string _workingDirectory;
    private readonly int _maxCheckpoints;
    private readonly string _sessionPrefix;
    private readonly List<CheckpointInfo> _checkpoints = [];
    private readonly SemaphoreSlim _lock = new(1, 1);
    private int _checkpointCounter;

    /// <summary>
    /// Creates a <see cref="PipeTarget"/> that reads and discards stdout output.
    /// Using a real pipe (rather than <see cref="PipeTarget.Null"/>) prevents SIGPIPE (exit 141)
    /// on Linux when the subprocess writes to a pipe whose read end is controlled by the test runner.
    /// </summary>
    private static PipeTarget DiscardPipe() => PipeTarget.ToStringBuilder(new StringBuilder());

    /// <summary>
    /// Initializes a new instance of the <see cref="GitCheckpointService"/> class.
    /// </summary>
    /// <param name="workingDirectory">The working directory for git operations.</param>
    /// <param name="sessionId">The session identifier used to scope stash message prefixes.</param>
    /// <param name="maxCheckpoints">Maximum checkpoints per session (default: 50). AT4 mitigation.</param>
    public GitCheckpointService(string workingDirectory, string sessionId, int maxCheckpoints = 50)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workingDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxCheckpoints);

        _workingDirectory = workingDirectory;
        // Use only the first 8 chars of the session ID to keep stash messages concise
        _sessionPrefix = $"krutaka-{sessionId[..Math.Min(8, sessionId.Length)]}";
        _maxCheckpoints = maxCheckpoints;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Returns <see cref="string.Empty"/> without throwing when:
    /// <list type="bullet">
    ///   <item><description>The working directory is not a git repository (AT11 graceful degradation).</description></item>
    ///   <item><description>The repository has no commits (stash requires at least one commit).</description></item>
    ///   <item><description>There are no local changes to stash (clean working tree).</description></item>
    /// </list>
    /// The working tree is restored after stashing (non-destructive): changes remain visible to the
    /// agent so subsequent tool calls can continue uninterrupted. The stash entry is kept as the
    /// rollback snapshot and can be applied via <see cref="RollbackToCheckpointAsync"/>.
    /// </remarks>
    public async Task<string> CreateCheckpointAsync(string message, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(message);

        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Graceful degradation: use git itself to detect repos (AT11). This handles regular
            // repos, worktrees (.git file), and repos created with --separate-git-dir.
            if (!await IsGitRepositoryAsync(cancellationToken).ConfigureAwait(false))
            {
                return string.Empty;
            }

            // git stash requires at least one commit to exist
            if (!await HasCommitsAsync(cancellationToken).ConfigureAwait(false))
            {
                return string.Empty;
            }

            // Count modified files before stashing (used to populate CheckpointInfo.FilesModified)
            int fileCount = await GetModifiedFileCountAsync(cancellationToken).ConfigureAwait(false);
            if (fileCount == 0)
            {
                return string.Empty; // Nothing to stash — clean working tree
            }

            // Enforce max checkpoint cap (AT4): prune oldest when at the limit
            if (_checkpoints.Count >= _maxCheckpoints)
            {
                await PruneOldestCheckpointAsync(cancellationToken).ConfigureAwait(false);
            }

            // Create the stash with a session-scoped message for easy identification
            var stashMessage = $"{_sessionPrefix}-{++_checkpointCounter}: {message}";
            var stashOutput = new StringBuilder();
            await Cli.Wrap("git")
                .WithArguments(["stash", "push", "--include-untracked", "-m", stashMessage])
                .WithWorkingDirectory(_workingDirectory)
                .WithStandardOutputPipe(PipeTarget.ToStringBuilder(stashOutput))
                .WithValidation(CommandResultValidation.None)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            // git outputs "No local changes to save" when the working tree is clean
            if (stashOutput.ToString().Contains("No local changes to save", StringComparison.OrdinalIgnoreCase))
            {
                _checkpointCounter--; // revert the counter increment
                return string.Empty;
            }

            // Retrieve the SHA of the newly created stash (refs/stash always points to latest)
            var shaOutput = new StringBuilder();
            var shaResult = await Cli.Wrap("git")
                .WithArguments(["rev-parse", "refs/stash"])
                .WithWorkingDirectory(_workingDirectory)
                .WithStandardOutputPipe(PipeTarget.ToStringBuilder(shaOutput))
                .WithValidation(CommandResultValidation.None)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            if (shaResult.ExitCode != 0)
            {
                _checkpointCounter--;
                return string.Empty;
            }

            var sha = shaOutput.ToString().Trim();
            if (string.IsNullOrEmpty(sha))
            {
                _checkpointCounter--;
                return string.Empty;
            }

            // Restore the working tree immediately so the checkpoint is non-destructive.
            // The stash entry remains as the rollback snapshot; the agent can keep working
            // against the same files without noticing the checkpoint was created.
            // If the apply fails (e.g., conflicts), we still return the SHA — the snapshot
            // is captured and remains available for manual rollback.
            var applyBackOutput = new StringBuilder();
            await Cli.Wrap("git")
                .WithArguments(["stash", "apply", "stash@{0}"])
                .WithWorkingDirectory(_workingDirectory)
                .WithStandardOutputPipe(PipeTarget.ToStringBuilder(applyBackOutput))
                .WithValidation(CommandResultValidation.None)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            _checkpoints.Add(new CheckpointInfo(sha, message, DateTime.UtcNow, fileCount));
            return sha;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Rollback sequence:
    /// <list type="number">
    ///   <item><description><c>git clean -fd</c> — removes untracked files added after the checkpoint.</description></item>
    ///   <item><description><c>git restore .</c> — resets tracked files to HEAD state.</description></item>
    ///   <item><description><c>git stash apply stash@{n}</c> — applies the checkpoint snapshot.</description></item>
    /// </list>
    /// The stash is applied (not popped), so it remains available for re-rollback.
    /// </remarks>
    public async Task RollbackToCheckpointAsync(string checkpointId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(checkpointId);

        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Ensure checkpoint belongs to this session
            var checkpoint = _checkpoints.FirstOrDefault(c => c.CheckpointId == checkpointId);
            if (checkpoint == null)
            {
                throw new InvalidOperationException(
                    $"Checkpoint '{checkpointId}' not found in the current session.");
            }

            // Locate the current stash index for this SHA (indices shift as new stashes are added)
            int stashIndex = await FindStashIndexAsync(checkpointId, cancellationToken).ConfigureAwait(false);
            if (stashIndex < 0)
            {
                throw new InvalidOperationException(
                    $"Stash for checkpoint '{checkpointId}' no longer exists in git stash.");
            }

            // Step 1: Remove untracked files that were added after the checkpoint
            await Cli.Wrap("git")
                .WithArguments(["clean", "-fd"])
                .WithWorkingDirectory(_workingDirectory)
                .WithStandardOutputPipe(DiscardPipe())
                .WithValidation(CommandResultValidation.None)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            // Step 2: Reset tracked files to HEAD state so the stash applies cleanly
            await Cli.Wrap("git")
                .WithArguments(["restore", "."])
                .WithWorkingDirectory(_workingDirectory)
                .WithStandardOutputPipe(DiscardPipe())
                .WithValidation(CommandResultValidation.None)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            // Step 3: Apply the checkpoint stash (apply, not pop — keeps it available)
            var applyOutput = new StringBuilder();
            var applyResult = await Cli.Wrap("git")
                .WithArguments(["stash", "apply", $"stash@{{{stashIndex}}}"])
                .WithWorkingDirectory(_workingDirectory)
                .WithStandardOutputPipe(PipeTarget.ToStringBuilder(applyOutput))
                .WithValidation(CommandResultValidation.None)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);

            if (applyResult.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"Failed to apply checkpoint '{checkpointId}'. Git exit code: {applyResult.ExitCode}");
            }
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyList<CheckpointInfo>> ListCheckpointsAsync(CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Return a defensive snapshot to prevent race conditions on the returned list
            return [.. _checkpoints];
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Returns <see langword="true"/> if <see cref="_workingDirectory"/> is inside a git repository.
    /// Uses <c>git rev-parse --git-dir</c> rather than checking for a <c>.git</c> directory so that
    /// worktrees (where <c>.git</c> is a file), repos with <c>--separate-git-dir</c>, and submodules
    /// are all correctly detected. Returns <see langword="false"/> when git is not installed.
    /// </summary>
    private async Task<bool> IsGitRepositoryAsync(CancellationToken cancellationToken)
    {
        var result = await Cli.Wrap("git")
            .WithArguments(["rev-parse", "--git-dir"])
            .WithWorkingDirectory(_workingDirectory)
            .WithStandardOutputPipe(DiscardPipe())
            .WithValidation(CommandResultValidation.None)
            .ExecuteAsync(cancellationToken)
            .ConfigureAwait(false);

        return result.ExitCode == 0;
    }

    /// <summary>
    /// Returns <see langword="true"/> if the git repository in <see cref="_workingDirectory"/>
    /// has at least one commit. Git stash requires a commit to exist.
    /// </summary>
    private async Task<bool> HasCommitsAsync(CancellationToken cancellationToken)
    {
        var result = await Cli.Wrap("git")
            .WithArguments(["rev-parse", "HEAD"])
            .WithWorkingDirectory(_workingDirectory)
            .WithStandardOutputPipe(DiscardPipe())
            .WithValidation(CommandResultValidation.None)
            .ExecuteAsync(cancellationToken)
            .ConfigureAwait(false);

        return result.ExitCode == 0;
    }

    /// <summary>
    /// Returns the number of changed files (tracked and untracked) in the working tree.
    /// Uses <c>git status --porcelain</c> for a stable, machine-readable output format.
    /// </summary>
    private async Task<int> GetModifiedFileCountAsync(CancellationToken cancellationToken)
    {
        var output = new StringBuilder();
        await Cli.Wrap("git")
            .WithArguments(["status", "--porcelain"])
            .WithWorkingDirectory(_workingDirectory)
            .WithStandardOutputPipe(PipeTarget.ToStringBuilder(output))
            .WithValidation(CommandResultValidation.None)
            .ExecuteAsync(cancellationToken)
            .ConfigureAwait(false);

        return output.ToString()
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Count(line => !string.IsNullOrWhiteSpace(line));
    }

    /// <summary>
    /// Searches <c>git stash list</c> for the given SHA and returns its current zero-based index.
    /// Returns -1 if the stash is not found (e.g., it was dropped externally).
    /// Stash indices are positional and shift as new stashes are created, so this lookup is
    /// performed at the point of use rather than cached.
    /// </summary>
    private async Task<int> FindStashIndexAsync(string sha, CancellationToken cancellationToken)
    {
        var output = new StringBuilder();
        await Cli.Wrap("git")
            .WithArguments(["stash", "list", "--format=%H"])
            .WithWorkingDirectory(_workingDirectory)
            .WithStandardOutputPipe(PipeTarget.ToStringBuilder(output))
            .WithValidation(CommandResultValidation.None)
            .ExecuteAsync(cancellationToken)
            .ConfigureAwait(false);

        var shas = output.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < shas.Length; i++)
        {
            if (string.Equals(shas[i].Trim(), sha, StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }

        return -1;
    }

    /// <summary>
    /// Prunes the oldest session checkpoint by dropping it from git stash and removing it
    /// from the in-memory list. Called when <see cref="_maxCheckpoints"/> is reached (AT4).
    /// </summary>
    private async Task PruneOldestCheckpointAsync(CancellationToken cancellationToken)
    {
        if (_checkpoints.Count == 0)
        {
            return;
        }

        var oldest = _checkpoints[0];
        int idx = await FindStashIndexAsync(oldest.CheckpointId, cancellationToken).ConfigureAwait(false);

        if (idx >= 0)
        {
            await Cli.Wrap("git")
                .WithArguments(["stash", "drop", $"stash@{{{idx}}}"])
                .WithWorkingDirectory(_workingDirectory)
                .WithStandardOutputPipe(DiscardPipe())
                .WithValidation(CommandResultValidation.None)
                .ExecuteAsync(cancellationToken)
                .ConfigureAwait(false);
        }

        // Always remove from in-memory list even if the stash was already gone externally
        _checkpoints.RemoveAt(0);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _lock.Dispose();
    }
}
