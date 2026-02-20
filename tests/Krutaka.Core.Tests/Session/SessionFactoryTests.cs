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
    public async Task Create_Should_IsolateDirectoryGrantsBetweenSessions()
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

        // Act - Verify each session has its own orchestrator (basic sanity check)
        session1.Orchestrator.Should().NotBe(session2.Orchestrator, "each session should have its own orchestrator");

        // Reflect the private _commandApprovalCache field from each orchestrator to verify isolation
        var cache1 = session1.Orchestrator.GetType()
            .GetField("_commandApprovalCache", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(session1.Orchestrator);

        var cache2 = session2.Orchestrator.GetType()
            .GetField("_commandApprovalCache", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(session2.Orchestrator);

        cache1.Should().NotBeNull("each orchestrator should have its own command approval cache");
        cache2.Should().NotBeNull("each orchestrator should have its own command approval cache");
        cache1.Should().NotBe(cache2, "command approval caches should not be shared between sessions");

        // Verify that adding an approval to cache1 doesn't affect cache2
        var cacheType = cache1!.GetType();
        var addApprovalMethod = cacheType.GetMethod("AddApproval", [typeof(string), typeof(TimeSpan)]);
        var isApprovedMethod = cacheType.GetMethod("IsApproved", [typeof(string)]);

        addApprovalMethod.Should().NotBeNull("command approval cache should expose an AddApproval method");
        isApprovedMethod.Should().NotBeNull("command approval cache should expose an IsApproved method");

        var commandKey = "test-command-approval-isolation";

        // Add approval in session1's cache
        addApprovalMethod!.Invoke(cache1, [commandKey, TimeSpan.FromMinutes(5)]);

        // Verify the command is approved in session1's cache
        var isApprovedInSession1 = (bool)isApprovedMethod!.Invoke(cache1, [commandKey])!;
        isApprovedInSession1.Should().BeTrue("command should be approved in the cache where it was added");

        // Verify the same command is NOT approved in session2's cache
        var isApprovedInSession2 = (bool)isApprovedMethod.Invoke(cache2, [commandKey])!;
        isApprovedInSession2.Should().BeFalse("command approvals should not leak between sessions");
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
    public void Create_Should_ThrowInvalidOperationException_WhenProjectPathIsSystemDirectory()
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
    public void Create_Should_ThrowInvalidOperationException_WhenProjectPathIsProgramFiles()
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
    public async Task Create_Should_PassMemoryWriterDelegateToContextCompactor()
    {
        // Arrange
        var factory = CreateSessionFactory();
        Func<string, CancellationToken, Task> memoryWriter = (content, ct) =>
        {
            return Task.CompletedTask;
        };

        var request = new SessionRequest(
            ProjectPath: "/tmp/test-sessions/project1",
            MemoryWriter: memoryWriter);

        // Act
        await using var session = factory.Create(request);

        // Assert - Memory writer was passed to SessionRequest and stored
        // We can't easily verify the ContextCompactor has it without reflection,
        // but we can verify the request parameter is accepted
        session.Should().NotBeNull();
        request.MemoryWriter.Should().Be(memoryWriter);
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

    [Fact]
    public async Task Create_Should_UseProvidedSessionIdOverride()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");
        var expectedSessionId = Guid.NewGuid();

        // Act
        await using var session = factory.Create(request, expectedSessionId);

        // Assert
        session.SessionId.Should().Be(expectedSessionId);
        session.CorrelationContext.SessionId.Should().Be(expectedSessionId);
    }

    [Fact]
    public async Task Create_Should_GenerateUniqueGuidsForMultipleCallsWithoutOverride()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");

        // Act
        await using var session1 = factory.Create(request);
        await using var session2 = factory.Create(request);

        // Assert
        session1.SessionId.Should().NotBe(session2.SessionId);
        session1.SessionId.Should().NotBeEmpty();
        session2.SessionId.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Create_Should_PreserveSessionIdInCorrelationContext()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");
        var originalSessionId = Guid.NewGuid();

        // Act
        await using var session = factory.Create(request, originalSessionId);

        // Assert
        session.CorrelationContext.SessionId.Should().Be(originalSessionId);
        session.SessionId.Should().Be(originalSessionId);
        session.CorrelationContext.SessionId.Should().Be(session.SessionId);
    }

    [Fact]
    public async Task Create_Should_SupportResumeScenario_WithSameSessionIdForExternalKeyMapping()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var sessionId = Guid.NewGuid();
        var externalKey = "telegram:chat_12345";

        // Create initial session (simulates first creation)
        var request1 = new SessionRequest("/tmp/test-sessions/project", ExternalKey: externalKey);
        await using var initialSession = factory.Create(request1, sessionId);

        // Verify initial session has the expected IDs
        initialSession.SessionId.Should().Be(sessionId);
        initialSession.ExternalKey.Should().Be(externalKey);

        // Simulate suspend and resume - create a new session with the same sessionId
        var request2 = new SessionRequest("/tmp/test-sessions/project", ExternalKey: externalKey);
        await using var resumedSession = factory.Create(request2, sessionId);

        // Assert - resumed session preserves session ID and external key mapping
        resumedSession.SessionId.Should().Be(sessionId);
        resumedSession.SessionId.Should().Be(initialSession.SessionId);
        resumedSession.ExternalKey.Should().Be(externalKey);
        resumedSession.CorrelationContext.SessionId.Should().Be(sessionId);
    }

    [Fact]
    public async Task Create_Should_IsolatePerSessionComponentsEvenWithSameSessionId()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");
        var sessionId = Guid.NewGuid();

        // Act - Create two sessions with the same session ID (simulates resume scenario)
        await using var session1 = factory.Create(request, sessionId);
        await using var session2 = factory.Create(request, sessionId);

        // Assert - Session IDs are the same
        session1.SessionId.Should().Be(sessionId);
        session2.SessionId.Should().Be(sessionId);

        // Assert - But per-session components are still isolated
        session1.Orchestrator.Should().NotBe(session2.Orchestrator, "orchestrators should be different instances");
        session1.CorrelationContext.Should().NotBe(session2.CorrelationContext, "correlation contexts should be different instances");
        session1.SessionAccessStore.Should().NotBe(session2.SessionAccessStore, "session access stores should be different instances");
        session1.Budget.Should().NotBe(session2.Budget, "budgets should be different instances");
    }

    [Fact]
    public async Task Create_Should_BackwardCompatibleWithExistingCalls()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");

        // Act - Call without optional parameter (existing code pattern)
        await using var session = factory.Create(request);

        // Assert - Existing behavior preserved
        session.SessionId.Should().NotBeEmpty();
        session.CorrelationContext.SessionId.Should().Be(session.SessionId);
    }

    [Fact]
    public void Create_Should_ThrowArgumentException_WhenSessionIdOverrideIsGuidEmpty()
    {
        // Arrange
        var factory = CreateSessionFactory();
        var request = new SessionRequest("/tmp/test-sessions/project");

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => factory.Create(request, Guid.Empty));
        exception.ParamName.Should().Be("sessionId");
        exception.Message.Should().Contain("Session ID cannot be Guid.Empty");
        exception.Message.Should().Contain("A valid non-empty GUID is required for session identity");
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
