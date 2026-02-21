#pragma warning disable CA2007 // Do not directly await a Task in tests
using System.Globalization;
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
    public async Task RunAsync_Should_ThrowTimeoutException_WhenApprovalTimeoutExceeded()
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

        // Create orchestrator with 1-second approval timeout
        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            securityPolicy,
            toolTimeoutSeconds: 30,
            approvalTimeoutSeconds: 1);

        // Act - don't approve, wait for timeout
        var act = async () =>
        {
            await foreach (var evt in orchestrator.RunAsync("Write file", "System prompt"))
            {
                if (evt is HumanApprovalRequired)
                {
                    // Intentionally do nothing here; orchestrator will hit its internal approval timeout.
                }
            }
        };

        // Assert
        await act.Should().ThrowAsync<TimeoutException>()
            .WithMessage("*Approval timeout*");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenApprovalTimeoutNegative()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var securityPolicy = new MockSecurityPolicy();

        // Act & Assert
        var act = () => new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            securityPolicy,
            approvalTimeoutSeconds: -1);

        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("approvalTimeoutSeconds");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenPruneToolResultsAfterTurnsNegative()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var securityPolicy = new MockSecurityPolicy();

        // Act & Assert
        var act = () => new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            securityPolicy,
            pruneToolResultsAfterTurns: -1);

        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("pruneToolResultsAfterTurns");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenPruneToolResultMinCharsNegative()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var securityPolicy = new MockSecurityPolicy();

        // Act & Assert
        var act = () => new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            securityPolicy,
            pruneToolResultMinChars: -1);

        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("pruneToolResultMinChars");
    }

    [Fact]
    public async Task RunAsync_Should_AllowInfiniteApprovalTimeout_WhenSetToZero()
    {
        // Arrange - timeout set to 0 = infinite
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var securityPolicy = new MockSecurityPolicy();

        securityPolicy.SetApprovalRequired("write_file", true);
        toolRegistry.AddTool("write_file", "{\"path\":\"test.txt\",\"content\":\"data\"}", "Success");

        // First response: tool use
        claudeClient.AddToolCallStarted("write_file", "tool_789", "{\"path\":\"test.txt\",\"content\":\"data\"}");
        claudeClient.AddFinalResponse("", "tool_use");

        // Second response: final answer
        claudeClient.AddFinalResponse("Done", "end_turn");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            securityPolicy,
            approvalTimeoutSeconds: 0); // Infinite

        // Act
        var events = new List<AgentEvent>();
        var runTask = Task.Run(async () =>
        {
            await foreach (var evt in orchestrator.RunAsync("Write file", "System prompt"))
            {
                events.Add(evt);
                if (evt is HumanApprovalRequired approval)
                {
                    // Approve after a delay (would timeout if limit was strict)
                    await Task.Delay(500);
                    orchestrator.ApproveTool(approval.ToolUseId);
                }
            }
        });

        // Assert - should complete without timeout (using Task.Wait with timeout)
        var completed = await Task.WhenAny(runTask, Task.Delay(TimeSpan.FromSeconds(5)));
        completed.Should().Be(runTask, "task should complete before timeout");
        await runTask; // Ensure no exceptions were thrown
        events.OfType<HumanApprovalRequired>().Should().ContainSingle();
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
    public async Task RunAsync_Should_TruncateOversizedToolResults()
    {
        // Arrange — tool returns a result larger than the 200K character limit
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();

        var oversizedResult = new string('x', 300_000); // 300K characters
        toolRegistry.AddTool("search_files", "{\"pattern\":\"TODO\"}", oversizedResult);

        // First response: tool use
        claudeClient.AddToolCallStarted("search_files", "tool_big", "{\"pattern\":\"TODO\"}");
        claudeClient.AddFinalResponse("", "tool_use");

        // Second response: final answer
        claudeClient.AddFinalResponse("Search complete", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient, toolRegistry);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Search for TODO", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert — tool completed (not failed) but result was truncated
        var completed = events.OfType<ToolCallCompleted>().Should().ContainSingle().Subject;
        completed.Result.Length.Should().BeLessThan(oversizedResult.Length,
            "oversized tool result should be truncated");
        completed.Result.Should().Contain("[Output truncated:",
            "truncation message should be appended");
        // Use invariant culture formatting to match production code
        var expectedSize = string.Create(CultureInfo.InvariantCulture, $"{300_000:N0}");
        completed.Result.Should().Contain($"{expectedSize} characters",
            "truncation message should include original size");
    }

    [Fact]
    public async Task RunAsync_Should_NotTruncateNormalToolResults()
    {
        // Arrange — tool returns a normal-sized result
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();

        var normalResult = "File contents here";
        toolRegistry.AddTool("read_file", "{\"path\":\"test.txt\"}", normalResult);

        // First response: tool use
        claudeClient.AddToolCallStarted("read_file", "tool_normal", "{\"path\":\"test.txt\"}");
        claudeClient.AddFinalResponse("", "tool_use");

        // Second response: final answer
        claudeClient.AddFinalResponse("Done", "end_turn");

        using var orchestrator = CreateOrchestrator(claudeClient, toolRegistry);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Read test.txt", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert — result should not be truncated
        var completed = events.OfType<ToolCallCompleted>().Should().ContainSingle().Subject;
        completed.Result.Should().Be(normalResult);
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

    [Fact]
    public async Task RunAsync_Should_TriggerCompaction_WhenTokenCountExceedsThreshold()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        // Configure CountTokensAsync to return a value above the threshold
        claudeClient.SetTokenCount(170_000); // Above 80% of 200K
        claudeClient.AddFinalResponse("Response after compaction", "end_turn");

        var compactor = new ContextCompactor(claudeClient);

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            new MockToolRegistry(),
            new MockSecurityPolicy(),
            contextCompactor: compactor);

        // Act - first turn creates history, but since compaction needs >6 messages
        // and mock token count is high, it will attempt compaction
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Test prompt", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert - should complete without error and CountTokensAsync should have been called
        // (once for compaction check inside the agentic loop)
        events.Should().ContainSingle(e => e is FinalResponse);
        claudeClient.CountTokensCallCount.Should().BeGreaterThanOrEqualTo(1,
            "CountTokensAsync must be called to evaluate whether compaction is needed");
    }

    [Fact]
    public async Task RunAsync_Should_RecomputeTokensAfter_EmergencyTruncation()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        // Set high token count to trigger compaction
        claudeClient.SetTokenCount(210_000); // Above hard limit of 200K to trigger emergency truncation
        claudeClient.AddFinalResponse("Response after truncation", "end_turn");

        var compactor = new ContextCompactor(claudeClient);

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            new MockToolRegistry(),
            new MockSecurityPolicy(),
            contextCompactor: compactor);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Test prompt", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert
        // When emergency truncation is triggered, CountTokensAsync should be called:
        // 1. Once to check if compaction is needed
        // 2. Once during compaction (CompactAsync)
        // 3. Once after TruncateToFitAsync to get accurate final token count
        // The exact count depends on implementation details, but should be >= 2
        claudeClient.CountTokensCallCount.Should().BeGreaterThanOrEqualTo(2,
            "CountTokensAsync must be called to check compaction need and recompute tokens after emergency truncation");

        // If CompactionCompleted event is emitted, verify it has been updated
        var compactionEvent = events.OfType<CompactionCompleted>().SingleOrDefault();
        if (compactionEvent != null)
        {
            // TokensAfter should reflect post-truncation count, not pre-truncation
            compactionEvent.TokensAfter.Should().BeGreaterThan(0, "TokensAfter must be set");
        }
    }

    [Fact]
    public async Task RunAsync_Should_UseDefaultLimit_WhenMaxToolResultCharactersNotSpecified()
    {
        // Arrange - tool result just under the default limit should NOT be truncated
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var resultUnderDefault = new string('x', AgentOrchestrator.DefaultMaxToolResultCharacters - 1);
        toolRegistry.AddTool("search", "{\"query\":\"test\"}", resultUnderDefault);

        claudeClient.AddToolCallStarted("search", "tool_def", "{\"query\":\"test\"}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        using var orchestrator = new AgentOrchestrator(claudeClient, toolRegistry, new MockSecurityPolicy());

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Search", "System"))
        {
            events.Add(evt);
        }

        // Assert - result should pass through without truncation
        var completed = events.OfType<ToolCallCompleted>().Single();
        completed.Result.Should().NotContain("[Output truncated:");
    }

    [Fact]
    public async Task RunAsync_Should_TruncateAtDefaultLimit_WhenMaxToolResultCharactersNotSpecified()
    {
        // Arrange - tool result above the default limit should be truncated
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var resultOverDefault = new string('x', AgentOrchestrator.DefaultMaxToolResultCharacters + 100);
        toolRegistry.AddTool("search", "{\"query\":\"test\"}", resultOverDefault);

        claudeClient.AddToolCallStarted("search", "tool_def2", "{\"query\":\"test\"}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        using var orchestrator = new AgentOrchestrator(claudeClient, toolRegistry, new MockSecurityPolicy());

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Search", "System"))
        {
            events.Add(evt);
        }

        // Assert - result should be truncated at the default limit
        var completed = events.OfType<ToolCallCompleted>().Single();
        completed.Result.Should().Contain("[Output truncated:");
    }

    [Fact]
    public async Task RunAsync_Should_FallBackToDefault_WhenMaxToolResultCharactersIsZero()
    {
        // Arrange - zero should fall back to default; result over default should be truncated
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var resultOverDefault = new string('x', AgentOrchestrator.DefaultMaxToolResultCharacters + 100);
        toolRegistry.AddTool("search", "{\"query\":\"test\"}", resultOverDefault);

        claudeClient.AddToolCallStarted("search", "tool_zero", "{\"query\":\"test\"}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        using var orchestrator = new AgentOrchestrator(
            claudeClient, toolRegistry, new MockSecurityPolicy(),
            maxToolResultCharacters: 0);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Search", "System"))
        {
            events.Add(evt);
        }

        // Assert - should truncate at default limit (not at 0)
        var completed = events.OfType<ToolCallCompleted>().Single();
        completed.Result.Should().Contain("[Output truncated:");
    }

    [Fact]
    public async Task RunAsync_Should_FallBackToDefault_WhenMaxToolResultCharactersIsNegative()
    {
        // Arrange - negative should fall back to default; result over default should be truncated
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var resultOverDefault = new string('x', AgentOrchestrator.DefaultMaxToolResultCharacters + 100);
        toolRegistry.AddTool("search", "{\"query\":\"test\"}", resultOverDefault);

        claudeClient.AddToolCallStarted("search", "tool_neg", "{\"query\":\"test\"}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        using var orchestrator = new AgentOrchestrator(
            claudeClient, toolRegistry, new MockSecurityPolicy(),
            maxToolResultCharacters: -100);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Search", "System"))
        {
            events.Add(evt);
        }

        // Assert - should truncate at default limit (not negative)
        var completed = events.OfType<ToolCallCompleted>().Single();
        completed.Result.Should().Contain("[Output truncated:");
    }

    [Fact]
    public async Task RunAsync_Should_TruncateToolResult_WhenExceedsCustomLimit()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        var customLimit = 100; // Very small limit for testing

        // Tool returns a result larger than the custom limit
        var largeResult = new string('x', 200);
        toolRegistry.AddTool("search", "{\"query\":\"test\"}", largeResult);

        // First response: tool use
        claudeClient.AddToolCallStarted("search", "tool_trunc", "{\"query\":\"test\"}");
        claudeClient.AddFinalResponse("", "tool_use");

        // Second response: final answer
        claudeClient.AddFinalResponse("Done", "end_turn");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            new MockSecurityPolicy(),
            maxToolResultCharacters: customLimit);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Search test", "System prompt"))
        {
            events.Add(evt);
        }

        // Assert - the tool call should complete (not fail) but with truncated content
        var completedEvents = events.OfType<ToolCallCompleted>().ToList();
        completedEvents.Should().ContainSingle();
        completedEvents[0].Result.Should().Contain("[Output truncated:");
        completedEvents[0].Result.Length.Should().BeLessThan(largeResult.Length + 200); // Allow room for truncation notice
    }

    [Fact]
    public void DefaultMaxToolResultCharacters_ShouldBe200000()
    {
        // Assert - verify the default constant value
        AgentOrchestrator.DefaultMaxToolResultCharacters.Should().Be(200_000);
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
        private int _tokenCount = 100;
        private int _countTokensCallCount;

        public int CountTokensCallCount => _countTokensCallCount;

        public void SetTokenCount(int count)
        {
            _tokenCount = count;
        }

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
            _countTokensCallCount++;
            return Task.FromResult(_tokenCount);
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

    [Fact]
    public async Task ClearConversationHistory_Should_ClearMessages()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddTextDelta("Response to hello");
        claudeClient.AddFinalResponse("", "end_turn");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            new MockToolRegistry(),
            new MockSecurityPolicy());

        // Run a conversation to add messages
        await foreach (var _ in orchestrator.RunAsync("Hello", "system"))
        {
            // Process events
        }

        orchestrator.ConversationHistory.Should().NotBeEmpty();

        // Act
        orchestrator.ClearConversationHistory();

        // Assert
        orchestrator.ConversationHistory.Should().BeEmpty();
    }

    // -------------------------------------------------------------------------
    // GitCheckpointService integration (v0.5.0)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RunAsync_Should_YieldCheckpointCreated_BeforeWriteFileTool()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("write_file", "{}", "File written");
        claudeClient.AddToolCallStarted("write_file", "wf-1", "{}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        var checkpointService = new MockCheckpointService();
        checkpointService.SetCheckpointId("abc123def456abc123def456abc123def456abcd");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            new MockSecurityPolicy(),
            checkpointService: checkpointService);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Write a file", "System"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<CheckpointCreated>().Should().ContainSingle("checkpoint created before write_file");
        var checkpointEvent = events.OfType<CheckpointCreated>().First();
        checkpointEvent.CheckpointId.Should().Be("abc123def456abc123def456abc123def456abcd");
        checkpointEvent.Message.Should().Be("pre-modify: write_file");
    }

    [Fact]
    public async Task RunAsync_Should_YieldCheckpointCreated_BeforeEditFileTool()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("edit_file", "{}", "File edited");
        claudeClient.AddToolCallStarted("edit_file", "ef-1", "{}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        var checkpointService = new MockCheckpointService();
        checkpointService.SetCheckpointId("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            new MockSecurityPolicy(),
            checkpointService: checkpointService);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Edit a file", "System"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<CheckpointCreated>().Should().ContainSingle("checkpoint created before edit_file");
        events.OfType<CheckpointCreated>().First().Message.Should().Be("pre-modify: edit_file");
    }

    [Fact]
    public async Task RunAsync_Should_NotYieldCheckpointCreated_ForNonFileModifyingTool()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("read_file", "{}", "File content");
        claudeClient.AddToolCallStarted("read_file", "rf-1", "{}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        var checkpointService = new MockCheckpointService();
        checkpointService.SetCheckpointId("shouldnotappear");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            new MockSecurityPolicy(),
            checkpointService: checkpointService);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Read a file", "System"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<CheckpointCreated>().Should().BeEmpty("read_file is not a file-modifying tool");
    }

    [Fact]
    public async Task RunAsync_Should_ContinueToolExecution_WhenCheckpointServiceFails()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("write_file", "{}", "File written successfully");
        claudeClient.AddToolCallStarted("write_file", "wf-fail", "{}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        var checkpointService = new MockCheckpointService();
        checkpointService.SetThrowOnCreate(new InvalidOperationException("Git not available"));

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            new MockSecurityPolicy(),
            checkpointService: checkpointService);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Write a file", "System"))
        {
            events.Add(evt);
        }

        // Assert — tool should execute despite checkpoint failure
        events.OfType<ToolCallCompleted>().Should().ContainSingle("tool executed despite checkpoint failure");
        events.OfType<CheckpointCreated>().Should().BeEmpty("checkpoint failed so no event");
    }

    [Fact]
    public async Task RunAsync_Should_NotYieldCheckpointCreated_WhenCheckpointReturnsEmpty()
    {
        // Arrange — checkpoint returns empty string (non-git dir or clean working tree)
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("write_file", "{}", "File written");
        claudeClient.AddToolCallStarted("write_file", "wf-empty", "{}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        var checkpointService = new MockCheckpointService();
        checkpointService.SetCheckpointId(string.Empty); // simulates non-git dir

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            new MockSecurityPolicy(),
            checkpointService: checkpointService);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Write a file", "System"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<CheckpointCreated>().Should().BeEmpty("empty ID means no checkpoint was created");
        events.OfType<ToolCallCompleted>().Should().ContainSingle("tool still executes");
    }

    [Fact]
    public async Task RunAsync_Should_YieldCheckpointRollbackAvailable_WhenAbortedWithCheckpoints()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        var toolRegistry = new MockToolRegistry();
        claudeClient.AddFinalResponse("Done", "end_turn");

        var stateManager = new AgentStateManager();
        stateManager.RequestAbort("Test abort");

        var checkpointService = new MockCheckpointService();
        // Simulate a pre-existing checkpoint in the service
        checkpointService.AddExistingCheckpoint(
            new CheckpointInfo("sha123abc", "before write", DateTime.UtcNow, 1));

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            new MockSecurityPolicy(),
            stateManager: stateManager,
            checkpointService: checkpointService);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Do something", "System"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<CheckpointRollbackAvailable>().Should().ContainSingle(
            "rollback available event should be emitted on abort with checkpoints");
        events.OfType<CheckpointRollbackAvailable>().First().CheckpointId.Should().Be("sha123abc");
    }

    [Fact]
    public async Task RunAsync_Should_NotYieldCheckpointRollbackAvailable_WhenNoCheckpointsExist()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddFinalResponse("Done", "end_turn");

        var stateManager = new AgentStateManager();
        stateManager.RequestAbort("Test abort");

        var checkpointService = new MockCheckpointService(); // No checkpoints

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            new MockToolRegistry(),
            new MockSecurityPolicy(),
            stateManager: stateManager,
            checkpointService: checkpointService);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Do something", "System"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<CheckpointRollbackAvailable>().Should().BeEmpty(
            "no rollback event when there are no checkpoints");
    }

    [Fact]
    public async Task RunAsync_Should_NotYieldCheckpointRollbackAvailable_WhenNotAborted()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddFinalResponse("Done", "end_turn");

        var checkpointService = new MockCheckpointService();
        checkpointService.AddExistingCheckpoint(
            new CheckpointInfo("sha123abc", "some checkpoint", DateTime.UtcNow, 1));

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            new MockToolRegistry(),
            new MockSecurityPolicy(),
            checkpointService: checkpointService);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Normal task", "System"))
        {
            events.Add(evt);
        }

        // Assert — no rollback event for a successful (non-aborted) run
        events.OfType<CheckpointRollbackAvailable>().Should().BeEmpty(
            "rollback event only emitted when agent is aborted");
    }

    /// <summary>
    /// Mock implementation of <see cref="IGitCheckpointService"/> for orchestrator tests.
    /// </summary>
    private sealed class MockCheckpointService : IGitCheckpointService
    {
        private string _checkpointId = string.Empty;
        private Exception? _throwOnCreate;
        private readonly List<CheckpointInfo> _existingCheckpoints = [];

        public void SetCheckpointId(string id) => _checkpointId = id;

        public void SetThrowOnCreate(Exception ex) => _throwOnCreate = ex;

        public void AddExistingCheckpoint(CheckpointInfo info) => _existingCheckpoints.Add(info);

        public Task<string> CreateCheckpointAsync(string message, CancellationToken cancellationToken)
        {
            if (_throwOnCreate != null)
            {
                throw _throwOnCreate;
            }

            return Task.FromResult(_checkpointId);
        }

        public Task RollbackToCheckpointAsync(string checkpointId, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<CheckpointInfo>> ListCheckpointsAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult<IReadOnlyList<CheckpointInfo>>(_existingCheckpoints.AsReadOnly());
        }
    }
}
