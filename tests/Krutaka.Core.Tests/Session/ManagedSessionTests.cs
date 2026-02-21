using FluentAssertions;

namespace Krutaka.Core.Tests;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Test objects are intentionally not disposed in test setup for constructor validation tests")]
public class ManagedSessionTests
{
    [Fact]
    public async Task DisposeAsync_Should_TransitionStateToTerminated()
    {
        // Arrange
        var session = CreateTestSession();

        // Act
        await session.DisposeAsync();

        // Assert
        session.State.Should().Be(SessionState.Terminated);
    }

    [Fact]
    public async Task DisposeAsync_Should_BeIdempotent()
    {
        // Arrange
        var session = CreateTestSession();

        // Act
        await session.DisposeAsync();
        await session.DisposeAsync(); // Second call should not throw

        // Assert
        session.State.Should().Be(SessionState.Terminated);
    }

    [Fact]
    public void UpdateLastActivity_Should_UpdateTimestamp()
    {
        // Arrange
        var session = CreateTestSession();
        var initialActivity = session.LastActivity;

        // Act - UpdateLastActivity should set timestamp to UtcNow
        session.UpdateLastActivity();

        // Assert - LastActivity should be at or after initial (within a reasonable tolerance)
        session.LastActivity.Should().BeOnOrAfter(initialActivity);
        session.LastActivity.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void Constructor_Should_InitializeProperties()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        var projectPath = "/test/path";
        var externalKey = "telegram:12345";
        var orchestrator = CreateMockOrchestrator();
        var correlationContext = new CorrelationContext();
        var budget = new SessionBudget(100_000, 50);

        // Act
        var session = new ManagedSession(sessionId, projectPath, externalKey, orchestrator, correlationContext, budget);

        // Assert
        session.SessionId.Should().Be(sessionId);
        session.ProjectPath.Should().Be(projectPath);
        session.ExternalKey.Should().Be(externalKey);
        session.Orchestrator.Should().Be(orchestrator);
        session.CorrelationContext.Should().Be(correlationContext);
        session.Budget.Should().Be(budget);
        session.State.Should().Be(SessionState.Active);
        session.CreatedAt.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));
        session.LastActivity.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenOrchestratorIsNull()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new ManagedSession(
                Guid.NewGuid(),
                "/test/path",
                null,
                null!,
                new CorrelationContext(),
                new SessionBudget(100_000, 50)));

        exception.ParamName.Should().Be("orchestrator");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenCorrelationContextIsNull()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new ManagedSession(
                Guid.NewGuid(),
                "/test/path",
                null,
                CreateMockOrchestrator(),
                null!,
                new SessionBudget(100_000, 50)));

        exception.ParamName.Should().Be("correlationContext");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenBudgetIsNull()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() =>
            new ManagedSession(
                Guid.NewGuid(),
                "/test/path",
                null,
                CreateMockOrchestrator(),
                new CorrelationContext(),
                null!));

        exception.ParamName.Should().Be("budget");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentException_WhenProjectPathIsNullOrWhitespace()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            new ManagedSession(
                Guid.NewGuid(),
                string.Empty,
                null,
                CreateMockOrchestrator(),
                new CorrelationContext(),
                new SessionBudget(100_000, 50)));

        exception.ParamName.Should().Be("projectPath");
    }

    [Fact]
    public void TaskBudgetTracker_Should_BeNullByDefault()
    {
        // Arrange & Act
        var session = CreateTestSession();

        // Assert — no tracker passed → property is null
        session.TaskBudgetTracker.Should().BeNull();
    }

    [Fact]
    public void TaskBudgetTracker_Should_ReturnPassedTracker()
    {
        // Arrange
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 100_000));

        // Act
        var session = new ManagedSession(
            Guid.NewGuid(),
            "/test/path",
            null,
            CreateMockOrchestrator(),
            new CorrelationContext(),
            new SessionBudget(100_000, 50),
            taskBudgetTracker: tracker);

        // Assert
        session.TaskBudgetTracker.Should().BeSameAs(tracker);
    }

    [Fact]
    public void GitCheckpointService_Should_BeNull_WhenNotProvided()
    {
        // Act
        var session = CreateTestSession();

        // Assert
        session.GitCheckpointService.Should().BeNull();
    }

    [Fact]
    public void GitCheckpointService_Should_ReturnPassedService()
    {
        // Arrange
        var checkpointService = new MockGitCheckpointService();

        // Act
        var session = new ManagedSession(
            Guid.NewGuid(),
            "/test/path",
            null,
            CreateMockOrchestrator(),
            new CorrelationContext(),
            new SessionBudget(100_000, 50),
            gitCheckpointService: checkpointService);

        // Assert
        session.GitCheckpointService.Should().BeSameAs(checkpointService);
    }

    [Fact]
    public async Task DisposeAsync_Should_DisposeGitCheckpointService_WhenProvided()
    {
        // Arrange
        var checkpointService = new DisposableMockGitCheckpointService();
        var session = new ManagedSession(
            Guid.NewGuid(),
            "/test/path",
            null,
            CreateMockOrchestrator(),
            new CorrelationContext(),
            new SessionBudget(100_000, 50),
            gitCheckpointService: checkpointService);

        // Act
        await session.DisposeAsync();

        // Assert
        checkpointService.IsDisposed.Should().BeTrue();
    }

    private static ManagedSession CreateTestSession()
    {
        return new ManagedSession(
            Guid.NewGuid(),
            "/test/path",
            null,
            CreateMockOrchestrator(),
            new CorrelationContext(),
            new SessionBudget(100_000, 50));
    }

    private static AgentOrchestrator CreateMockOrchestrator()
    {
        // Create a minimal working orchestrator for testing
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var securityPolicy = new MockSecurityPolicy();

        return new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            securityPolicy,
            toolTimeoutSeconds: 30,
            approvalTimeoutSeconds: 300,
            auditLogger: null,
            correlationContext: null,
            sessionAccessStore: null,
            contextCompactor: null);
    }

    private sealed class MockClaudeClient : IClaudeClient
    {
        public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.CompletedTask.ConfigureAwait(false);
            yield break;
        }

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(0);
        }
    }

    private sealed class MockToolRegistry : IToolRegistry
    {
        public void Register(ITool tool) { }
        public object GetToolDefinitions() => new object();
        public Task<string> ExecuteAsync(string toolName, System.Text.Json.JsonElement input, CancellationToken cancellationToken)
        {
            return Task.FromResult(string.Empty);
        }
    }

    private sealed class MockSecurityPolicy : ISecurityPolicy
    {
        public bool IsApprovalRequired(string toolName) => false;

        public string ValidatePath(string path, string workingDirectory, CorrelationContext? correlationContext = null)
        {
            return path;
        }

        public void ValidateCommand(string command, IEnumerable<string> arguments, CorrelationContext? correlationContext = null)
        {
        }

        public IDictionary<string, string?> ScrubEnvironment(IDictionary<string, string?> environment)
        {
            return environment;
        }
    }

    private sealed class MockGitCheckpointService : IGitCheckpointService
    {
        public Task<string> CreateCheckpointAsync(string message, CancellationToken cancellationToken)
            => Task.FromResult("cp-test-123");

        public Task RollbackToCheckpointAsync(string checkpointId, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task<IReadOnlyList<CheckpointInfo>> ListCheckpointsAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<CheckpointInfo>>([]);
    }

    private sealed class DisposableMockGitCheckpointService : IGitCheckpointService, IDisposable
    {
        public bool IsDisposed { get; private set; }

        public void Dispose() => IsDisposed = true;

        public Task<string> CreateCheckpointAsync(string message, CancellationToken cancellationToken)
            => Task.FromResult("cp-test-123");

        public Task RollbackToCheckpointAsync(string checkpointId, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task<IReadOnlyList<CheckpointInfo>> ListCheckpointsAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<CheckpointInfo>>([]);
    }
}
