#pragma warning disable CA2007 // Do not directly await a Task in tests
using System.Runtime.CompilerServices;
using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.Core.Tests;

/// <summary>
/// Unit tests for AgentOrchestrator agentic loop implementation.
/// </summary>
public sealed class AgentOrchestratorTests
{
    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenClaudeClientIsNull()
    {
        // Arrange
        var toolRegistry = new MockToolRegistry();
        var securityPolicy = new MockSecurityPolicy();

        // Act & Assert
        var act = () => new AgentOrchestrator(null!, toolRegistry, securityPolicy);
        act.Should().Throw<ArgumentNullException>().WithParameterName("claudeClient");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenToolRegistryIsNull()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var securityPolicy = new MockSecurityPolicy();

        // Act & Assert
        var act = () => new AgentOrchestrator(claudeClient, null!, securityPolicy);
        act.Should().Throw<ArgumentNullException>().WithParameterName("toolRegistry");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenSecurityPolicyIsNull()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();

        // Act & Assert
        var act = () => new AgentOrchestrator(claudeClient, toolRegistry, null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("securityPolicy");
    }

    [Fact]
    public async Task RunAsync_Should_ThrowArgumentException_WhenUserPromptIsNull()
    {
        // Arrange
        using var orchestrator = CreateOrchestrator();

        // Act
        var act = async () =>
        {
            await foreach (var _ in orchestrator.RunAsync(null!, "system prompt"))
            {
                // Empty - we expect an exception before any events are yielded
            }
        };

        // Assert
        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("userPrompt");
    }

    [Fact]
    public async Task RunAsync_Should_ThrowArgumentException_WhenUserPromptIsWhitespace()
    {
        // Arrange
        using var orchestrator = CreateOrchestrator();

        // Act
        var act = async () =>
        {
            await foreach (var _ in orchestrator.RunAsync("   ", "system prompt"))
            {
                // Empty - we expect an exception before any events are yielded
            }
        };

        // Assert
        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("userPrompt");
    }

    [Fact]
    public async Task RunAsync_Should_ThrowArgumentException_WhenSystemPromptIsNull()
    {
        // Arrange
        using var orchestrator = CreateOrchestrator();

        // Act
        var act = async () =>
        {
            await foreach (var _ in orchestrator.RunAsync("user prompt", null!))
            {
                // Empty - we expect an exception before any events are yielded
            }
        };

        // Assert
        await act.Should().ThrowAsync<ArgumentException>().WithParameterName("systemPrompt");
    }

    [Fact]
    public async Task RunAsync_Should_YieldTextDeltaEvents_WhenClaudeStreamsText()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddTextDelta("Hello");
        claudeClient.AddTextDelta(" world");
        claudeClient.AddFinalResponse("Hello world", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Test prompt", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert
        events.Should().HaveCountGreaterOrEqualTo(3);
        events.OfType<TextDelta>().Should().HaveCount(2);
        events.OfType<TextDelta>().Select(e => e.Text).Should().ContainInOrder("Hello", " world");
        events.OfType<FinalResponse>().Should().ContainSingle();
    }

    [Fact]
    public async Task RunAsync_Should_SetCorrelationRequestId_WhenRequestIdCaptured()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddRequestIdCaptured("req_test_12345");
        claudeClient.AddFinalResponse("Done", "end_turn");

        var correlationContext = new CorrelationContext();
        using var orchestrator = CreateOrchestrator(claudeClient, correlationContext: correlationContext);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Test prompt", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<RequestIdCaptured>().Should().ContainSingle();
        events.OfType<RequestIdCaptured>().First().RequestId.Should().Be("req_test_12345");
        correlationContext.RequestId.Should().Be("req_test_12345");
    }

    [Fact]
    public async Task RunAsync_Should_SetCorrelationRequestId_BeforeYielding()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddRequestIdCaptured("req_early_stop");
        claudeClient.AddFinalResponse("Done", "end_turn");

        var correlationContext = new CorrelationContext();
        using var orchestrator = CreateOrchestrator(claudeClient, correlationContext: correlationContext);

        // Act - stop enumerating immediately after receiving RequestIdCaptured
        await foreach (var evt in orchestrator.RunAsync("Test prompt", "System prompt"))
        {
            if (evt is RequestIdCaptured)
            {
                break;
            }
        }

        // Assert - correlation context should already be set even though we stopped early
        correlationContext.RequestId.Should().Be("req_early_stop");
    }

    [Fact]
    public async Task RunAsync_Should_ClearStaleRequestId_BeforeNewRequest()
    {
        // Arrange
        var correlationContext = new CorrelationContext();
        correlationContext.SetRequestId("stale_request_id");

        var claudeClient = new MockClaudeClient();
        claudeClient.AddFinalResponse("Done", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient, correlationContext: correlationContext);

        // Act
        await foreach (var _ in orchestrator.RunAsync("Test prompt", "System prompt"))
        {
            // consume all events
        }

        // Assert - stale request-id should be cleared (no new RequestIdCaptured was emitted)
        correlationContext.RequestId.Should().BeNull();
    }

    [Fact]
    public async Task RunAsync_Should_ProcessToolCalls_WhenClaudeRequestsTools()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("read_file", "{\"path\":\"test.txt\"}", "File contents");

        // First response: tool use
        claudeClient.AddToolCallStarted("read_file", "tool_123", "{\"path\":\"test.txt\"}");
        claudeClient.AddFinalResponse("", "tool_use");

        // Second response: final answer
        claudeClient.AddTextDelta("The file contains: File contents");
        claudeClient.AddFinalResponse("The file contains: File contents", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient, toolRegistry);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Read test.txt", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<ToolCallStarted>().Should().ContainSingle();
        events.OfType<ToolCallCompleted>().Should().ContainSingle();
        events.OfType<FinalResponse>().Should().HaveCount(2);

        // Verify tool was executed
        toolRegistry.ExecutedTools.Should().ContainSingle();
        toolRegistry.ExecutedTools[0].Should().Be("read_file");
    }

    [Fact]
    public async Task RunAsync_Should_YieldHumanApprovalRequired_WhenToolRequiresApproval()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var securityPolicy = new MockSecurityPolicy();

        securityPolicy.SetApprovalRequired("write_file", true);
        toolRegistry.AddTool("write_file", "{\"path\":\"test.txt\",\"content\":\"data\"}", "Success");

        // First response: tool use
        claudeClient.AddToolCallStarted("write_file", "tool_456", "{\"path\":\"test.txt\",\"content\":\"data\"}");
        claudeClient.AddFinalResponse("", "tool_use");

        // Second response: final answer
        claudeClient.AddFinalResponse("File written", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient, toolRegistry, securityPolicy);

        // Act - approve the tool when the approval event is received
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Write file", "System prompt"))
        {
            events.Add(evt);
            if (evt is HumanApprovalRequired approval)
            {
                orchestrator.ApproveTool(approval.ToolUseId);
            }
        }

        // Assert
        events.OfType<HumanApprovalRequired>().Should().ContainSingle();
        var approvalEvent = events.OfType<HumanApprovalRequired>().First();
        approvalEvent.ToolName.Should().Be("write_file");
        approvalEvent.ToolUseId.Should().Be("tool_456");
    }

    [Fact]
    public async Task RunAsync_Should_HandleToolExecutionFailure_WithoutCrashingLoop()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();

        toolRegistry.SetToolFailure("read_file", "File not found");

        // First response: tool use
        claudeClient.AddToolCallStarted("read_file", "tool_789", "{\"path\":\"missing.txt\"}");
        claudeClient.AddFinalResponse("", "tool_use");

        // Second response: handle error
        claudeClient.AddFinalResponse("File was not found", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient, toolRegistry);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Read missing file", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<ToolCallFailed>().Should().ContainSingle();
        var failedEvent = events.OfType<ToolCallFailed>().First();
        failedEvent.ToolName.Should().Be("read_file");
        failedEvent.Error.Should().Contain("File not found");
    }

    [Fact]
    public async Task RunAsync_Should_AddMessagesToConversationHistory()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddFinalResponse("Hello!", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient);

        // Act
        await foreach (var _ in orchestrator.RunAsync("Hi", "System prompt"))
        {
            // Intentionally iterate to drive the orchestrator and populate conversation history
        }

        // Assert
        orchestrator.ConversationHistory.Should().HaveCountGreaterOrEqualTo(2);
        // Should have user message and assistant message
    }

    [Fact]
    public async Task RunAsync_Should_ProcessMultipleToolCalls_InSingleResponse()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();

        toolRegistry.AddTool("read_file", "{\"path\":\"file1.txt\"}", "Content 1");
        toolRegistry.AddTool("read_file", "{\"path\":\"file2.txt\"}", "Content 2");

        // First response: multiple tool uses
        claudeClient.AddToolCallStarted("read_file", "tool_1", "{\"path\":\"file1.txt\"}");
        claudeClient.AddToolCallStarted("read_file", "tool_2", "{\"path\":\"file2.txt\"}");
        claudeClient.AddFinalResponse("", "tool_use");

        // Second response: final answer
        claudeClient.AddFinalResponse("Files processed", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient, toolRegistry);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Read files", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<ToolCallStarted>().Should().HaveCount(2);
        events.OfType<ToolCallCompleted>().Should().HaveCount(2);
        toolRegistry.ExecutedTools.Should().HaveCount(2);
    }

    [Fact]
    public void Dispose_Should_ReleaseResources()
    {
        // Arrange
        var orchestrator = CreateOrchestrator();

        // Act
        orchestrator.Dispose();

        // Assert - should not throw
        orchestrator.Dispose(); // Double dispose should be safe
    }

    [Fact]
    public async Task RunAsync_Should_SerializeTurnExecution()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        // Configure two batches for two separate calls
        claudeClient.AddFinalResponse("Response 1", "end_turn");
        claudeClient.AddFinalResponse("Response 2", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient);

        // Act - start two concurrent runs
        var task1 = Task.Run(async () =>
        {
            var count = 0;
            await foreach (var _ in orchestrator.RunAsync("Prompt 1", "System"))
            {
                count++;
                await Task.Delay(1); // Minimal delay to simulate processing
            }

            return count;
        });

        var task2 = Task.Run(async () =>
        {
            var count = 0;
            await foreach (var _ in orchestrator.RunAsync("Prompt 2", "System"))
            {
                count++;
                await Task.Delay(1); // Minimal delay to simulate processing
            }

            return count;
        });

        // Assert - both should complete without deadlock (serialized execution enforced by SemaphoreSlim)
        var results = await Task.WhenAll(task1, task2);
        results.Should().AllSatisfy(r => r.Should().BeGreaterThan(0));
    }

    private static AgentOrchestrator CreateOrchestrator(
        MockClaudeClient? claudeClient = null,
        MockToolRegistry? toolRegistry = null,
        MockSecurityPolicy? securityPolicy = null,
        int toolTimeoutSeconds = 30,
        CorrelationContext? correlationContext = null)
    {
        return new AgentOrchestrator(
            claudeClient ?? new MockClaudeClient(),
            toolRegistry ?? new MockToolRegistry(),
            securityPolicy ?? new MockSecurityPolicy(),
            toolTimeoutSeconds,
            correlationContext: correlationContext);
    }

    // Mock implementations for testing

    private sealed class MockClaudeClient : IClaudeClient
    {
        private readonly List<List<AgentEvent>> _eventBatches = [];

        public void AddTextDelta(string text)
        {
            EnsureCurrentBatch();
            _eventBatches[^1].Add(new TextDelta(text));
        }

        public void AddRequestIdCaptured(string requestId)
        {
            EnsureCurrentBatch();
            _eventBatches[^1].Add(new RequestIdCaptured(requestId));
        }

        public void AddToolCallStarted(string name, string id, string input)
        {
            EnsureCurrentBatch();
            _eventBatches[^1].Add(new ToolCallStarted(name, id, input));
        }

        public void AddFinalResponse(string content, string stopReason)
        {
            EnsureCurrentBatch();
            _eventBatches[^1].Add(new FinalResponse(content, stopReason));
            // Start a new batch for the next call
            _eventBatches.Add([]);
        }

        private void EnsureCurrentBatch()
        {
            if (_eventBatches.Count == 0)
            {
                _eventBatches.Add([]);
            }
        }

        private int _callIndex;

        public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();

            if (_callIndex < _eventBatches.Count)
            {
                var events = _eventBatches[_callIndex];
                _callIndex++;
                foreach (var evt in events)
                {
                    yield return evt;
                }
            }
        }

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(100);
        }
    }

    private sealed class MockToolRegistry : IToolRegistry
    {
        private readonly Dictionary<string, (string expectedInput, string result)> _tools = [];
        private readonly Dictionary<string, string> _failures = [];
        private readonly List<string> _executedTools = [];

        public List<string> ExecutedTools => _executedTools;

        public void AddTool(string name, string expectedInput, string result)
        {
            _tools[name] = (expectedInput, result);
        }

        public void SetToolFailure(string name, string errorMessage)
        {
            _failures[name] = errorMessage;
        }

        public void Register(ITool tool)
        {
            // Not used in tests
        }

        public object GetToolDefinitions()
        {
            return Array.Empty<object>();
        }

        public Task<string> ExecuteAsync(string name, JsonElement input, CancellationToken cancellationToken)
        {
            _executedTools.Add(name);

            if (_failures.TryGetValue(name, out var errorMessage))
            {
                throw new InvalidOperationException(errorMessage);
            }

            if (_tools.TryGetValue(name, out var toolInfo))
            {
                return Task.FromResult(toolInfo.result);
            }

            return Task.FromResult("Tool executed");
        }
    }

    private sealed class MockSecurityPolicy : ISecurityPolicy
    {
        private readonly Dictionary<string, bool> _approvalRequirements = [];

        public void SetApprovalRequired(string toolName, bool required)
        {
            _approvalRequirements[toolName] = required;
        }

        public bool IsApprovalRequired(string toolName)
        {
            return _approvalRequirements.TryGetValue(toolName, out var required) && required;
        }

        public string ValidatePath(string path, string allowedRoot, CorrelationContext? correlationContext = null)
        {
            return path;
        }

        public void ValidateCommand(string executable, IEnumerable<string> arguments, CorrelationContext? correlationContext = null)
        {
            // No validation in mock
        }

        public IDictionary<string, string?> ScrubEnvironment(IDictionary<string, string?> environment)
        {
            // Return a copy in mock
            return new Dictionary<string, string?>(environment);
        }
    }
}
