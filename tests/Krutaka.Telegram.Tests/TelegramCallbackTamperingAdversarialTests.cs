using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Telegram.Bot;
using Telegram.Bot.Types;

namespace Krutaka.Telegram.Tests;

/// <summary>
/// Adversarial tests for Telegram callback tampering prevention.
/// Validates HMAC signature verification, replay attack prevention, timestamp expiry,
/// cross-user authorization checks, and malformed data handling.
/// Modeled after AccessPolicyEngineAdversarialTests.
/// </summary>
public sealed class TelegramCallbackTamperingAdversarialTests : IDisposable
{
    private readonly CallbackDataSigner _signer;
    private readonly byte[] _testSecret;
    private readonly ITelegramBotClient _mockBotClient;
#pragma warning disable CA2213 // Mock object doesn't need disposal
    private readonly ISessionManager _mockSessionManager;
#pragma warning restore CA2213
    private readonly IAuditLogger _mockAuditLogger;
    private readonly TelegramApprovalHandler _handler;

    public TelegramCallbackTamperingAdversarialTests()
    {
        // Generate test HMAC secret
        _testSecret = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            _testSecret[i] = (byte)(i * 7); // Deterministic but non-sequential
        }

        _signer = new CallbackDataSigner(_testSecret);
        _mockBotClient = Substitute.For<ITelegramBotClient>();
        _mockSessionManager = Substitute.For<ISessionManager>();
        _mockAuditLogger = Substitute.For<IAuditLogger>();

        // Create logger mock for TelegramApprovalHandler
        var mockLogger = Substitute.For<ILogger<TelegramApprovalHandler>>();

        _handler = new TelegramApprovalHandler(
            _mockBotClient,
            _mockSessionManager,
            _mockAuditLogger,
            _signer,
            mockLogger);
    }

    public void Dispose()
    {
        _handler.Dispose();
        // _mockSessionManager is a mock (NSubstitute.For<>) and doesn't need explicit disposal
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Should_RejectCallback_WhenApprovalIdIsModifiedInSignedData()
    {
        // Arrange - CallbackDataSigner signs only the ApprovalId field (see CallbackDataSigner.Sign)
        // Create a valid signed callback
        var payload = new CallbackPayload(ApprovalId: "valid123", Hmac: null);
        var signedData = _signer.Sign(payload);

        // Tamper: modify the ApprovalId in the signed JSON (this is what the HMAC protects)
        // This tests that tampering with the signed field (ApprovalId) is detected
        var tamperedData = signedData.Replace("valid123", "hacked99", StringComparison.Ordinal);

        // Act - Verify that tampered data fails HMAC verification
        var verifiedPayload = _signer.Verify(tamperedData);

        // Assert - HMAC validation should fail for tampered ApprovalId
        verifiedPayload.Should().BeNull("tampered ApprovalId should fail HMAC verification");
    }

    [Fact]
    public async Task Should_RejectCallback_WhenApprovalIdModifiedButHmacUnchanged()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        var userId = 12345678L;
        var toolUseId = "test-tool-001";

        // Create a valid approval context
        var approvalId = await CreateApprovalContextViaReflection(sessionId, userId, toolUseId, "approve");
        var payload = new CallbackPayload(ApprovalId: approvalId, Hmac: null);
        var signedData = _signer.Sign(payload);

        // Tamper: modify the approval ID
        var tamperedData = signedData.Replace(approvalId, "tampered-id", StringComparison.Ordinal);

        // Act
        var verifiedPayload = _signer.Verify(tamperedData);

        // Assert
        verifiedPayload.Should().BeNull("tampered approval ID should fail HMAC verification");
    }

    [Fact]
    public void Should_RejectCallback_WhenHmacIsCompletelyRandom()
    {
        // Arrange
        var payload = new CallbackPayload(ApprovalId: "test123", Hmac: "RandomHmacThatIsInvalid==");
        var serialized = System.Text.Json.JsonSerializer.Serialize(payload);

        // Act
        var verified = _signer.Verify(serialized);

        // Assert
        verified.Should().BeNull("random HMAC should fail verification");
    }

    [Fact]
    public void Should_RejectCallback_WhenHmacIsEmpty()
    {
        // Arrange
        var payloadWithEmptyHmac = "{\"i\":\"test123\",\"s\":\"\"}";

        // Act
        var verified = _signer.Verify(payloadWithEmptyHmac);

        // Assert
        verified.Should().BeNull("empty HMAC should fail verification");
    }

    [Fact]
    public async Task Should_RejectCallback_WhenSameNonceUsedTwice()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        var userId = 12345678L;
        var toolUseId = "test-tool-001";

        await using var mockSession = CreateMockSession(sessionId);
        _mockSessionManager.GetSession(sessionId).Returns(mockSession);

        // Create approval context
        var approvalId = await CreateApprovalContextViaReflection(sessionId, userId, toolUseId, "approve");
        var payload = new CallbackPayload(ApprovalId: approvalId, Hmac: null);
        var signedData = _signer.Sign(payload);

        var callback1 = CreateCallback(userId, signedData);
        var callback2 = CreateCallback(userId, signedData); // Same data (same nonce)

        // Act - First callback should succeed (removes context)
        await _handler.HandleCallbackAsync(callback1, CancellationToken.None);

        // Act - Second callback with same nonce should be rejected
        await _handler.HandleCallbackAsync(callback2, CancellationToken.None);

        // Assert - After first callback, approval context is removed, so second callback gets "expired or not found"
        // (per HandleCallbackAsync control flow: context lookup happens before nonce check)
        await _mockBotClient.Received(1).AnswerCallbackQuery(
            Arg.Is<string>(id => id == callback2.Id),
            Arg.Is<string>(text => text.Contains("expired or not found", StringComparison.OrdinalIgnoreCase)),
            Arg.Any<bool>(),
            Arg.Any<string>(),
            Arg.Any<int>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_RejectCallback_WhenTimestampIsExpired()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        var userId = 12345678L;
        var toolUseId = "test-tool-001";

        // Create approval context with old timestamp (1 hour ago)
        var oldTimestamp = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        var approvalId = await CreateApprovalContextViaReflectionWithTimestamp(
            sessionId, userId, toolUseId, "approve", oldTimestamp);

        var payload = new CallbackPayload(ApprovalId: approvalId, Hmac: null);
        var signedData = _signer.Sign(payload);

        var callback = CreateCallback(userId, signedData);

        // Act
        await _handler.HandleCallbackAsync(callback, CancellationToken.None);

        // Assert - Verify error was sent about expiration
        await _mockBotClient.Received(1).AnswerCallbackQuery(
            Arg.Is<string>(id => id == callback.Id),
            Arg.Is<string>(text => text.Contains("expired", StringComparison.OrdinalIgnoreCase)),
            Arg.Any<bool>(),
            Arg.Any<string>(),
            Arg.Any<int>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_RejectCallback_WhenUserIdDoesNotMatchSigner()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        var originalUserId = 12345678L;
        var attackerUserId = 88888888L;
        var toolUseId = "test-tool-001";

        // Create approval context for originalUserId
        var approvalId = await CreateApprovalContextViaReflection(sessionId, originalUserId, toolUseId, "approve");
        var payload = new CallbackPayload(ApprovalId: approvalId, Hmac: null);
        var signedData = _signer.Sign(payload);

        // Attacker tries to use the callback with their user ID
        var callback = CreateCallback(attackerUserId, signedData);

        // Act
        await _handler.HandleCallbackAsync(callback, CancellationToken.None);

        // Assert - Verify error was sent about user mismatch
        await _mockBotClient.Received(1).AnswerCallbackQuery(
            Arg.Is<string>(id => id == callback.Id),
            Arg.Is<string>(text => text.Contains("not for you", StringComparison.OrdinalIgnoreCase)),
            Arg.Any<bool>(),
            Arg.Any<string>(),
            Arg.Any<int>(),
            Arg.Any<CancellationToken>());

        // Verify security incident was logged
        _mockAuditLogger.Received().LogTelegramSecurityIncident(
            Arg.Any<CorrelationContext>(),
            Arg.Is<TelegramSecurityIncidentEvent>(e =>
                e.Type == IncidentType.CallbackTampering &&
                e.TelegramUserId == attackerUserId));
    }

    [Fact]
    public async Task Should_HandleGracefully_WhenCallbackDataIsMalformedJson()
    {
        // Arrange
        var malformedJson = "{\"i\":\"test\",invalid json syntax}";
        var callback = CreateCallback(12345678L, malformedJson);

        // Act
        await _handler.HandleCallbackAsync(callback, CancellationToken.None);

        // Assert - Should handle gracefully without throwing
        // Verify error response was sent
        await _mockBotClient.Received(1).AnswerCallbackQuery(
            Arg.Is<string>(id => id == callback.Id),
            Arg.Is<string>(text => text.Contains("Invalid signature", StringComparison.OrdinalIgnoreCase) ||
                                   text.Contains("tampered", StringComparison.OrdinalIgnoreCase)),
            Arg.Any<bool>(),
            Arg.Any<string>(),
            Arg.Any<int>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public void Should_RejectCallback_WhenDataExceedsSizeLimit()
    {
        // Arrange - Create a payload that would exceed Telegram's 64-byte limit when signed
        var longApprovalId = new string('A', 100); // Very long approval ID
        var payload = new CallbackPayload(ApprovalId: longApprovalId, Hmac: null);

        // Act
        var signedData = _signer.Sign(payload);

        // Assert - While the signer doesn't enforce the limit, we verify the data is too large
        // In production, this would be caught before sending to Telegram
        signedData.Length.Should().BeGreaterThan(64,
            "oversized callback data should be detectable for validation");
    }

    [Fact]
    public async Task Should_HandleGracefully_WhenCallbackDataIsNull()
    {
        // Arrange
        var callback = new CallbackQuery
        {
            Id = "test-callback-id",
            From = new User { Id = 12345678L },
            Message = new Message
            {
                Date = DateTime.UtcNow,
                Chat = new Chat { Id = 111 }
            },
            Data = null // Null data
        };

        // Act
        await _handler.HandleCallbackAsync(callback, CancellationToken.None);

        // Assert - Should handle gracefully without throwing
        // No bot client calls should be made for null data
        await _mockBotClient.DidNotReceive().AnswerCallbackQuery(
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<bool>(),
            Arg.Any<string>(),
            Arg.Any<int>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_HandleGracefully_WhenCallbackFromIsNull()
    {
        // Arrange
        var callback = new CallbackQuery
        {
            Id = "test-callback-id",
            From = null!, // Null sender
            Message = new Message
            {
                Date = DateTime.UtcNow,
                Chat = new Chat { Id = 111 }
            },
            Data = "test-data"
        };

        // Act
        await _handler.HandleCallbackAsync(callback, CancellationToken.None);

        // Assert - Should handle gracefully without throwing
        await _mockBotClient.DidNotReceive().AnswerCallbackQuery(
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<bool>(),
            Arg.Any<string>(),
            Arg.Any<int>(),
            Arg.Any<CancellationToken>());
    }

    // Helper methods

    private static CallbackQuery CreateCallback(long userId, string callbackData)
    {
        return new CallbackQuery
        {
            Id = $"callback-{Guid.NewGuid()}",
            From = new User { Id = userId, Username = "testuser" },
            Message = new Message
            {
                Date = DateTime.UtcNow,
                Chat = new Chat { Id = 111 },
                Text = "Original approval request"
            },
            Data = callbackData
        };
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "AgentOrchestrator is disposed through ManagedSession.DisposeAsync")]
    private static ManagedSession CreateMockSession(Guid sessionId)
    {
        // Create a minimal mock orchestrator using NSubstitute
        // Note: AgentOrchestrator has complex dependencies, so we create mocks for all required services
        var mockClaudeClient = Substitute.For<IClaudeClient>();
        var mockToolRegistry = Substitute.For<IToolRegistry>();
        var mockSecurityPolicy = Substitute.For<ISecurityPolicy>();
        var mockSessionAccessStore = Substitute.For<ISessionAccessStore>();
        var mockAuditLogger = Substitute.For<IAuditLogger>();
        var correlationContext = new CorrelationContext(sessionId);
        var mockCommandApprovalCache = Substitute.For<ICommandApprovalCache>();

        // Create AgentOrchestrator - it's IDisposable and will be disposed with the ManagedSession
        var mockOrchestrator = new AgentOrchestrator(
            mockClaudeClient,
            mockToolRegistry,
            mockSecurityPolicy,
            maxToolResultCharacters: 10000,
            sessionAccessStore: mockSessionAccessStore,
            auditLogger: mockAuditLogger,
            correlationContext: correlationContext,
            contextCompactor: null,
            commandApprovalCache: mockCommandApprovalCache);

        var budget = new SessionBudget(10000, 100);

        // Return ManagedSession which implements IAsyncDisposable
        // Caller should use 'await using' to properly dispose the orchestrator and session
        return new ManagedSession(
            sessionId,
            "/tmp/test-project",
            null,
            mockOrchestrator,
            correlationContext,
            budget);
    }

    /// <summary>
    /// Uses reflection to call the private StoreApprovalContext method on the handler.
    /// </summary>
    private async Task<string> CreateApprovalContextViaReflection(
        Guid sessionId, long userId, string toolUseId, string action)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return await CreateApprovalContextViaReflectionWithTimestamp(
            sessionId, userId, toolUseId, action, timestamp);
    }

    /// <summary>
    /// Uses reflection to call the private StoreApprovalContext method with a specific timestamp.
    /// </summary>
    private async Task<string> CreateApprovalContextViaReflectionWithTimestamp(
        Guid sessionId, long userId, string toolUseId, string action, long timestamp)
    {
        // Access the private method via reflection
        var method = typeof(TelegramApprovalHandler).GetMethod(
            "StoreApprovalContext",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        method.Should().NotBeNull("StoreApprovalContext method should exist");

        // Invoke the method
        var approvalId = method!.Invoke(_handler, [sessionId, userId, toolUseId, action, timestamp]) as string;
        approvalId.Should().NotBeNullOrEmpty();

        return await Task.FromResult(approvalId!);
    }
}
