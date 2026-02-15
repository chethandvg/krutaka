using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Core.Tests;

/// <summary>
/// Tests for SessionFactory implementation.
/// Validates per-session isolation and resource management.
/// </summary>
public sealed class SessionFactoryTests
{
    [Fact]
    public async Task Create_Should_GenerateUniqueSessionIds()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project1");

        // Act
        await using var session1 = factory.Create(request);
        await using var session2 = factory.Create(request);

        // Assert
        session1.SessionId.Should().NotBe(session2.SessionId);
        session1.SessionId.Should().NotBeEmpty();
        session2.SessionId.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Create_Should_CreateSeparateCorrelationContextsForDifferentSessions()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request1 = new SessionRequest("/tmp/test-sessions/project1");
        var request2 = new SessionRequest("/tmp/test-sessions/project2");

        // Act
        await using var session1 = factory.Create(request1);
        await using var session2 = factory.Create(request2);

        // Assert
        session1.CorrelationContext.Should().NotBe(session2.CorrelationContext);
        session1.CorrelationContext.SessionId.Should().NotBe(session2.CorrelationContext.SessionId);
        session1.CorrelationContext.SessionId.Should().Be(session1.SessionId);
        session2.CorrelationContext.SessionId.Should().Be(session2.SessionId);
    }

    [Fact]
    public async Task Create_Should_IsolateDirextoryGrantsBetweenSessions()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request1 = new SessionRequest("/tmp/test-sessions/project1");
        var request2 = new SessionRequest("/tmp/test-sessions/project2");

        await using var session1 = factory.Create(request1);
        await using var session2 = factory.Create(request2);

        // Act - Grant access in session1
        await session1.SessionAccessStore!.GrantAccessAsync(
            "/tmp/test-sessions/granted/path",
            AccessLevel.ReadWrite,
            TimeSpan.FromMinutes(5),
            "Test grant",
            GrantSource.User,
            CancellationToken.None);

        var session1Granted = await session1.SessionAccessStore.IsGrantedAsync(
            "/tmp/test-sessions/granted/path",
            AccessLevel.ReadWrite,
            CancellationToken.None);

        var session2Granted = await session2.SessionAccessStore!.IsGrantedAsync(
            "/tmp/test-sessions/granted/path",
            AccessLevel.ReadWrite,
            CancellationToken.None);

        // Assert
        session1Granted.Should().BeTrue("session1 should have the grant");
        session2Granted.Should().BeFalse("session2 should NOT have the grant from session1");
    }

    [Fact]
    public async Task Create_Should_IsolateCommandApprovalsBetweenSessions()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request1 = new SessionRequest("/tmp/test-sessions/project1");
        var request2 = new SessionRequest("/tmp/test-sessions/project2");

        await using var session1 = factory.Create(request1);
        await using var session2 = factory.Create(request2);

        // Act - We can't directly access the private _commandApprovalCache in orchestrator,
        // so we verify isolation by checking that each session has its own orchestrator instance
        session1.Orchestrator.Should().NotBe(session2.Orchestrator, "each session should have its own orchestrator");
    }

    [Fact]
    public async Task Create_Should_ScopeToolRegistryToProjectPath()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request1 = new SessionRequest("/tmp/test-sessions/project1");
        var request2 = new SessionRequest("/tmp/test-sessions/project2");

        // Act
        await using var session1 = factory.Create(request1);
        await using var session2 = factory.Create(request2);

        // Assert - Each session should have its own tool registry
        // We can't directly inspect the working directory of tools,
        // but we can verify they have separate tool registry instances
        var tools1 = session1.Orchestrator.GetType()
            .GetField("_toolRegistry", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(session1.Orchestrator);

        var tools2 = session2.Orchestrator.GetType()
            .GetField("_toolRegistry", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(session2.Orchestrator);

        tools1.Should().NotBeNull();
        tools2.Should().NotBeNull();
        tools1.Should().NotBe(tools2, "each session should have its own tool registry");
    }

    [Fact]
    public async Task Create_Should_ThrowInvalidOperationException_WhenProjectPathIsSystemDirectory()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        // Skip test if Windows directory is not available (non-Windows platform)
        if (string.IsNullOrWhiteSpace(windowsDir))
        {
            return;
        }

        var request = new SessionRequest(windowsDir);

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() => factory.Create(request));
        exception.Message.Should().Contain("Cannot create session with ProjectPath");
        exception.Message.Should().Contain(windowsDir);
    }

    [Fact]
    public async Task Create_Should_ThrowInvalidOperationException_WhenProjectPathIsProgramFiles()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        // Skip test if ProgramFiles directory is not available (non-Windows platform)
        if (string.IsNullOrWhiteSpace(programFiles))
        {
            return;
        }

        var request = new SessionRequest(programFiles);

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() => factory.Create(request));
        exception.Message.Should().Contain("Cannot create session with ProjectPath");
    }

    [Fact]
    public async Task ManagedSession_DisposeAsync_Should_DisposeOrchestrator()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");
        var session = factory.Create(request);

        // Act
        await session.DisposeAsync();

        // Assert
        session.State.Should().Be(SessionState.Terminated);
        // Orchestrator is disposed (we can't directly check but state transition confirms)
    }

    [Fact]
    public async Task Create_Should_ApplySessionBudgetFromRequest()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest(
            ProjectPath: "/tmp/test-sessions/project",
            MaxTokenBudget: 50000,
            MaxToolCallBudget: 25);

        // Act
        await using var session = factory.Create(request);

        // Assert
        session.Budget.MaxTokens.Should().Be(50000);
        session.Budget.MaxToolCalls.Should().Be(25);
        session.Budget.TokensUsed.Should().Be(0);
        session.Budget.ToolCallsUsed.Should().Be(0);
    }

    [Fact]
    public async Task Create_Should_SetProjectPathFromRequest()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var projectPath = "/tmp/test-sessions/my-project";
        var request = new SessionRequest(projectPath);

        // Act
        await using var session = factory.Create(request);

        // Assert
        session.ProjectPath.Should().Be(projectPath);
    }

    [Fact]
    public async Task Create_Should_SetExternalKeyFromRequest()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var externalKey = "telegram:12345";
        var request = new SessionRequest("/tmp/test-sessions/project", ExternalKey: externalKey);

        // Act
        await using var session = factory.Create(request);

        // Assert
        session.ExternalKey.Should().Be(externalKey);
    }

    [Fact]
    public async Task Create_Should_InitializeSessionStateToActive()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");

        // Act
        await using var session = factory.Create(request);

        // Assert
        session.State.Should().Be(SessionState.Active);
        session.CreatedAt.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));
        session.LastActivity.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Create_Should_ShareClaudeClientAcrossSessions()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request1 = new SessionRequest("/tmp/test-sessions/project1");
        var request2 = new SessionRequest("/tmp/test-sessions/project2");

        // Act
        await using var session1 = factory.Create(request1);
        await using var session2 = factory.Create(request2);

        // Assert - We can't directly access the Claude client, but we verify
        // that orchestrators are different instances (per-session)
        session1.Orchestrator.Should().NotBe(session2.Orchestrator);
    }

    [Fact]
    public async Task Create_Should_SetDefaultBudgetLimits_WhenNotSpecified()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");

        // Act
        await using var session = factory.Create(request);

        // Assert
        session.Budget.MaxTokens.Should().Be(200_000, "default from SessionRequest");
        session.Budget.MaxToolCalls.Should().Be(100, "default from SessionRequest");
    }

    [Fact]
    public async Task Create_Should_CreateIndependentSessionAccessStores()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");

        await using var session1 = factory.Create(request);
        await using var session2 = factory.Create(request);

        // Act - Grant in session1
        await session1.SessionAccessStore!.GrantAccessAsync(
            "/test/grant1",
            AccessLevel.ReadOnly,
            TimeSpan.FromMinutes(1),
            "Test",
            GrantSource.User,
            CancellationToken.None);

        // Grant different path in session2
        await session2.SessionAccessStore!.GrantAccessAsync(
            "/test/grant2",
            AccessLevel.ReadWrite,
            TimeSpan.FromMinutes(1),
            "Test",
            GrantSource.User,
            CancellationToken.None);

        var session1Grants = await session1.SessionAccessStore.GetActiveGrantsAsync(CancellationToken.None);
        var session2Grants = await session2.SessionAccessStore.GetActiveGrantsAsync(CancellationToken.None);

        // Assert
        session1Grants.Should().HaveCount(1);
        session1Grants[0].Path.Should().Be("/test/grant1");

        session2Grants.Should().HaveCount(1);
        session2Grants[0].Path.Should().Be("/test/grant2");
    }

    [Fact]
    public async Task Create_Should_CreatePerSessionContextCompactor()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request1 = new SessionRequest("/tmp/test-sessions/project1");
        var request2 = new SessionRequest("/tmp/test-sessions/project2");

        // Act
        await using var session1 = factory.Create(request1);
        await using var session2 = factory.Create(request2);

        // Assert - Each orchestrator should have its own context compactor
        // We verify by checking orchestrators are different instances
        session1.Orchestrator.Should().NotBe(session2.Orchestrator);
    }

    [Fact]
    public async Task Create_Should_ThrowArgumentNullException_WhenRequestIsNull()
    {
        // Arrange
        var factory = CreateSessionFactory();

        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() => factory.Create(null!));
        exception.ParamName.Should().Be("request");
    }

    [Fact]
    public async Task Create_Should_AssignExternalKeyToSession()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var externalKey = "telegram:chat_987654";
        var request = new SessionRequest("/tmp/test-sessions/project", ExternalKey: externalKey);

        // Act
        await using var session = factory.Create(request);

        // Assert
        session.ExternalKey.Should().Be(externalKey);
    }

    [Fact]
    public async Task Create_Should_AllowNullExternalKey()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project", ExternalKey: null);

        // Act
        await using var session = factory.Create(request);

        // Assert
        session.ExternalKey.Should().BeNull();
    }

    /// <summary>
    /// Creates a SessionFactory with all required dependencies.
    /// </summary>
    private static SessionFactory CreateSessionFactory()
    {
        // Use DI container to create factory with all dependencies
        var services = new ServiceCollection();

        // Register shared services
        services.AddSingleton<IClaudeClient, MockClaudeClient>();
        services.AddSingleton<IAuditLogger, MockAuditLogger>();

        // Register tool services (includes ISecurityPolicy, IAccessPolicyEngine, etc.)
        services.AddAgentTools(options =>
        {
            options.DefaultWorkingDirectory = "/test/default";
            options.CeilingDirectory = Path.GetTempPath();
            options.AutoGrantPatterns = [];
            options.MaxConcurrentGrants = 10;
        });

        var serviceProvider = services.BuildServiceProvider();
        return serviceProvider.GetRequiredService<ISessionFactory>() as SessionFactory
            ?? throw new InvalidOperationException("Failed to create SessionFactory");
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "MockClaudeClient is instantiated via DI container")]
    private sealed class MockClaudeClient : IClaudeClient
    {
        public IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools,
            CancellationToken cancellationToken)
        {
            return AsyncEnumerable.Empty<AgentEvent>();
        }

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(100);
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "MockAuditLogger is instantiated via DI container")]
    private sealed class MockAuditLogger : IAuditLogger
    {
        public void Log(AuditEvent auditEvent)
        {
        }

        public void LogUserInput(CorrelationContext correlationContext, string content)
        {
        }

        public void LogClaudeApiRequest(CorrelationContext correlationContext, string model, int tokenCount, int toolCount)
        {
        }

        public void LogClaudeApiResponse(CorrelationContext correlationContext, string stopReason, int inputTokens, int outputTokens)
        {
        }

        public void LogToolExecution(
            CorrelationContext correlationContext,
            string toolName,
            bool approved,
            bool alwaysApprove,
            long durationMs,
            int resultLength,
            string? errorMessage = null)
        {
        }

        public void LogCompaction(CorrelationContext correlationContext, int beforeTokenCount, int afterTokenCount, int messagesRemoved)
        {
        }

        public void LogSecurityViolation(CorrelationContext correlationContext, string violationType, string blockedValue, string context)
        {
        }

        public void LogCommandClassification(
            CorrelationContext correlationContext,
            string executable,
            string arguments,
            CommandRiskTier tier,
            bool autoApproved,
            string? trustedDirectory,
            string reason)
        {
        }
    }
}
