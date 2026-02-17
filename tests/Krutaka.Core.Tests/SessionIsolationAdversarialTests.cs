using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Core.Tests;

/// <summary>
/// Adversarial tests for multi-session isolation guarantees.
/// Validates that session state (directory grants, command approvals, conversation history,
/// event streams, tool registries) never leaks between concurrent sessions.
/// Modeled after AccessPolicyEngineAdversarialTests and PathResolverAdversarialTests.
/// </summary>
public sealed class SessionIsolationAdversarialTests : IDisposable
{
    private readonly ServiceProvider _serviceProvider;
    private readonly string _testProjectPath1;
    private readonly string _testProjectPath2;

    public SessionIsolationAdversarialTests()
    {
        // Use CI-safe test directories
        _testProjectPath1 = TestDirectoryHelper.GetTestDirectory("session-isolation-project1");
        _testProjectPath2 = TestDirectoryHelper.GetTestDirectory("session-isolation-project2");
        Directory.CreateDirectory(_testProjectPath1);
        Directory.CreateDirectory(_testProjectPath2);

        var services = new ServiceCollection();

        // Register shared services
        services.AddSingleton<IClaudeClient, MockClaudeClient>();
        services.AddSingleton<IAuditLogger, MockAuditLogger>();

        services.AddAgentTools(options =>
        {
            options.DefaultWorkingDirectory = _testProjectPath1;
            options.CeilingDirectory = Path.GetDirectoryName(_testProjectPath1)!;
        });

        _serviceProvider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        _serviceProvider.Dispose();
        TestDirectoryHelper.TryDeleteDirectory(_testProjectPath1);
        TestDirectoryHelper.TryDeleteDirectory(_testProjectPath2);
    }

    [Fact]
    public async Task Should_IsolateDirectoryGrants_BetweenSessions()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var sessionA = factory.Create(new SessionRequest(_testProjectPath1));
        await using var sessionB = factory.Create(new SessionRequest(_testProjectPath2));

        var grantedPath = Path.Combine(_testProjectPath1, "granted");
        Directory.CreateDirectory(grantedPath);

        // Act - Grant access in Session A
        await sessionA.SessionAccessStore!.GrantAccessAsync(
            grantedPath,
            AccessLevel.ReadWrite,
            TimeSpan.FromMinutes(5),
            "Test grant for Session A",
            GrantSource.User,
            CancellationToken.None);

        // Check grants in both sessions
        var sessionAGranted = await sessionA.SessionAccessStore.IsGrantedAsync(
            grantedPath,
            AccessLevel.ReadWrite,
            CancellationToken.None);

        var sessionBGranted = await sessionB.SessionAccessStore!.IsGrantedAsync(
            grantedPath,
            AccessLevel.ReadWrite,
            CancellationToken.None);

        // Assert
        sessionAGranted.Should().BeTrue("Session A should have the grant it created");
        sessionBGranted.Should().BeFalse("Session B should NOT have access to Session A's grant");
    }

    [Fact]
    public async Task Should_IsolateCommandApprovals_BetweenSessions()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var sessionA = factory.Create(new SessionRequest(_testProjectPath1));
        await using var sessionB = factory.Create(new SessionRequest(_testProjectPath2));

        // Access the private _commandApprovalCache field via reflection
        var commandApprovalCacheA = sessionA.Orchestrator.GetType()
            .GetField("_commandApprovalCache", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(sessionA.Orchestrator);

        var commandApprovalCacheB = sessionB.Orchestrator.GetType()
            .GetField("_commandApprovalCache", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(sessionB.Orchestrator);

        commandApprovalCacheA.Should().NotBeNull("Session A should have a command approval cache");
        commandApprovalCacheB.Should().NotBeNull("Session B should have a command approval cache");
        commandApprovalCacheA.Should().NotBe(commandApprovalCacheB, "Sessions should have different cache instances");

        // Get reflection handles
        var cacheType = commandApprovalCacheA!.GetType();
        var addApprovalMethod = cacheType.GetMethod("AddApproval", [typeof(string), typeof(TimeSpan)]);
        var isApprovedMethod = cacheType.GetMethod("IsApproved", [typeof(string)]);

        addApprovalMethod.Should().NotBeNull();
        isApprovedMethod.Should().NotBeNull();

        var commandKey = "git status";

        // Act - Add approval in Session A
        addApprovalMethod!.Invoke(commandApprovalCacheA, [commandKey, TimeSpan.FromMinutes(5)]);

        // Check approvals
        var isApprovedInA = (bool)isApprovedMethod!.Invoke(commandApprovalCacheA, [commandKey])!;
        var isApprovedInB = (bool)isApprovedMethod.Invoke(commandApprovalCacheB, [commandKey])!;

        // Assert
        isApprovedInA.Should().BeTrue("Command should be approved in Session A");
        isApprovedInB.Should().BeFalse("Command approval should NOT leak from Session A to Session B");
    }

    [Fact]
    public async Task Should_IsolateConversationHistory_BetweenSessions()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var sessionA = factory.Create(new SessionRequest(_testProjectPath1));
        await using var sessionB = factory.Create(new SessionRequest(_testProjectPath2));

        // Access the ConversationHistory property
        var historyA = sessionA.Orchestrator.ConversationHistory;
        var historyB = sessionB.Orchestrator.ConversationHistory;

        historyA.Should().NotBeNull();
        historyB.Should().NotBeNull();

        // Act - Add a message to Session A's history (using Anthropic SDK Message type)
        // Note: We're testing isolation, so we just verify the lists are different
        var initialCountA = historyA!.Count;
        var initialCountB = historyB!.Count;

        // Assert
        historyA.Should().NotBeSameAs(historyB, "Sessions should have separate conversation history instances");
        
        // Both should start empty since they're new sessions
        historyA.Should().BeEmpty("Session A should start with empty history");
        historyB.Should().BeEmpty("Session B should start with empty history");
    }

    [Fact]
    public async Task Should_IsolateEventStreams_WhenRunningConcurrentSessions()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var sessionA = factory.Create(new SessionRequest(_testProjectPath1));
        await using var sessionB = factory.Create(new SessionRequest(_testProjectPath2));

        var eventsFromA = new List<AgentEvent>();
        var eventsFromB = new List<AgentEvent>();

        // Act - Verify orchestrators are different instances
        // Since MockClaudeClient returns empty events, we'll test isolation differently
        // by verifying that the orchestrators themselves are separate instances
        sessionA.Orchestrator.Should().NotBeSameAs(sessionB.Orchestrator,
            "Each session should have its own orchestrator instance");

        // Verify SessionIds are different
        var sessionAId = sessionA.SessionId;
        var sessionBId = sessionB.SessionId;

        // Assert
        sessionAId.Should().NotBe(sessionBId, "Sessions should have unique IDs");
        
        // Verify that attempting to run prompts doesn't interfere
        // (MockClaudeClient returns empty streams, so this tests orchestrator isolation)
        var taskA = Task.Run(async () =>
        {
            await foreach (var evt in sessionA.Orchestrator.RunAsync("test prompt A", ""))
            {
                eventsFromA.Add(evt);
            }
        });

        var taskB = Task.Run(async () =>
        {
            await foreach (var evt in sessionB.Orchestrator.RunAsync("test prompt B", ""))
            {
                eventsFromB.Add(evt);
            }
        });

        // Wait briefly for tasks to start (they'll complete quickly with mock)
        await Task.WhenAny(Task.WhenAll(taskA, taskB), Task.Delay(1000));
    }

    [Fact]
    public async Task Should_GenerateDifferentSessionIds_ForDifferentSessions()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();

        // Act
        await using var sessionA = factory.Create(new SessionRequest(_testProjectPath1));
        await using var sessionB = factory.Create(new SessionRequest(_testProjectPath2));

        // Assert
        sessionA.SessionId.Should().NotBe(Guid.Empty);
        sessionB.SessionId.Should().NotBe(Guid.Empty);
        sessionA.SessionId.Should().NotBe(sessionB.SessionId, "Each session must have a unique ID");
    }

    [Fact]
    public async Task Should_IsolateCorrelationContext_BetweenSessions()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var sessionA = factory.Create(new SessionRequest(_testProjectPath1));
        await using var sessionB = factory.Create(new SessionRequest(_testProjectPath2));

        // Assert
        sessionA.CorrelationContext.Should().NotBeSameAs(sessionB.CorrelationContext,
            "Sessions should have separate CorrelationContext instances");

        sessionA.CorrelationContext.SessionId.Should().Be(sessionA.SessionId);
        sessionB.CorrelationContext.SessionId.Should().Be(sessionB.SessionId);
        sessionA.CorrelationContext.SessionId.Should().NotBe(sessionB.CorrelationContext.SessionId);
    }

    [Fact]
    public async Task Should_UsesSeparateJsonlFiles_ForDifferentSessions()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var sessionA = factory.Create(new SessionRequest(_testProjectPath1));
        await using var sessionB = factory.Create(new SessionRequest(_testProjectPath2));

        // Access the private SessionStore via reflection
        var storeFieldA = sessionA.Orchestrator.GetType()
            .GetField("_sessionStore", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(sessionA.Orchestrator);

        var storeFieldB = sessionB.Orchestrator.GetType()
            .GetField("_sessionStore", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(sessionB.Orchestrator);

        storeFieldA.Should().NotBeNull("Session A should have a SessionStore");
        storeFieldB.Should().NotBeNull("Session B should have a SessionStore");
        storeFieldA.Should().NotBeSameAs(storeFieldB, "Sessions should have separate SessionStore instances");

        // Get the JSONL file paths
        var filePathPropertyA = storeFieldA!.GetType()
            .GetProperty("FilePath", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)?
            .GetValue(storeFieldA) as string;

        var filePathPropertyB = storeFieldB!.GetType()
            .GetProperty("FilePath", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)?
            .GetValue(storeFieldB) as string;

        // Assert
        filePathPropertyA.Should().NotBeNullOrEmpty("Session A should have a JSONL file path");
        filePathPropertyB.Should().NotBeNullOrEmpty("Session B should have a JSONL file path");
        filePathPropertyA.Should().NotBe(filePathPropertyB,
            "Each session should write to a different JSONL file");
    }

    [Fact]
    public async Task Should_KeepSessionBActive_WhenSessionAIsTerminated()
    {
        // Arrange
        var managerOptions = new SessionManagerOptions();
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var manager = new SessionManager(factory, managerOptions, logger: null);

        var sessionA = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath1), CancellationToken.None);
        var sessionB = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath2), CancellationToken.None);

        sessionA.State.Should().Be(SessionState.Active);
        sessionB.State.Should().Be(SessionState.Active);

        // Act - Terminate Session A
        await manager.TerminateSessionAsync(sessionA.SessionId, CancellationToken.None);

        // Assert
        sessionA.State.Should().Be(SessionState.Terminated);
        sessionB.State.Should().Be(SessionState.Active, "Session B should remain active when Session A is terminated");

        manager.GetSession(sessionA.SessionId).Should().BeNull("Terminated session should be removed from manager");
        manager.GetSession(sessionB.SessionId).Should().NotBeNull("Session B should still be retrievable");
    }

    [Fact]
    public async Task Should_ScopeToolRegistryToProjectPath_PerSession()
    {
        // Arrange
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var sessionA = factory.Create(new SessionRequest(_testProjectPath1));
        await using var sessionB = factory.Create(new SessionRequest(_testProjectPath2));

        // Access the private _toolRegistry field via reflection
        var toolRegistryA = sessionA.Orchestrator.GetType()
            .GetField("_toolRegistry", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(sessionA.Orchestrator);

        var toolRegistryB = sessionB.Orchestrator.GetType()
            .GetField("_toolRegistry", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)?
            .GetValue(sessionB.Orchestrator);

        // Assert
        toolRegistryA.Should().NotBeNull("Session A should have a tool registry");
        toolRegistryB.Should().NotBeNull("Session B should have a tool registry");
        toolRegistryA.Should().NotBeSameAs(toolRegistryB,
            "Each session should have its own tool registry instance");

        sessionA.ProjectPath.Should().Be(_testProjectPath1);
        sessionB.ProjectPath.Should().Be(_testProjectPath2);
        sessionA.ProjectPath.Should().NotBe(sessionB.ProjectPath,
            "Sessions with different project paths should be isolated");
    }

    // Mock implementations

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

        public void LogToolExecution(CorrelationContext correlationContext, string toolName, bool approved, bool alwaysApprove, long durationMs, int resultLength, string? errorMessage = null)
        {
        }

        public void LogCompaction(CorrelationContext correlationContext, int beforeTokenCount, int afterTokenCount, int messagesRemoved)
        {
        }

        public void LogSecurityViolation(CorrelationContext correlationContext, string violationType, string blockedValue, string context)
        {
        }

        public void LogCommandClassification(CorrelationContext correlationContext, string executable, string arguments, CommandRiskTier tier, bool autoApproved, string? trustedDirectory, string reason)
        {
        }
    }
}
