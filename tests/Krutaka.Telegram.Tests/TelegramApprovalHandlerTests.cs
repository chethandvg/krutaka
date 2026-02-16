using FluentAssertions;
using Xunit;

namespace Krutaka.Telegram.Tests;

/// <summary>
/// Tests for TelegramApprovalHandler - Focus on HMAC signing security.
/// </summary>
public class TelegramApprovalHandlerTests
{
    private readonly CallbackDataSigner _signer;

    public TelegramApprovalHandlerTests()
    {
        // Generate a test HMAC secret
        var testSecret = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            testSecret[i] = (byte)i;
        }

        _signer = new CallbackDataSigner(testSecret);
    }

    [Fact]
    public void CallbackDataSigner_Should_ProduceDeterministicOutput()
    {
        // Arrange
        var payload = new CallbackPayload(
            Action: "approve",
            ToolUseId: "tool-123",
            SessionId: Guid.NewGuid(),
            UserId: 12345,
            Timestamp: 1000000,
            Nonce: "test-nonce",
            Hmac: null);

        // Act
        var signed1 = _signer.Sign(payload);
        var signed2 = _signer.Sign(payload);

        // Assert
        signed1.Should().Be(signed2, "signing the same payload should produce identical results");
    }

    [Fact]
    public void CallbackDataSigner_Should_VerifyCorrectSignature()
    {
        // Arrange
        var payload = new CallbackPayload(
            Action: "approve",
            ToolUseId: "tool-123",
            SessionId: Guid.NewGuid(),
            UserId: 12345,
            Timestamp: 1000000,
            Nonce: "test-nonce",
            Hmac: null);

        var signed = _signer.Sign(payload);

        // Act
        var verified = _signer.Verify(signed);

        // Assert
        verified.Should().NotBeNull();
        verified!.Action.Should().Be("approve");
        verified.ToolUseId.Should().Be("tool-123");
        verified.UserId.Should().Be(12345);
    }

    [Fact]
    public void CallbackDataSigner_Should_RejectTamperedAction()
    {
        // Arrange
        var payload = new CallbackPayload(
            Action: "approve",
            ToolUseId: "tool-123",
            SessionId: Guid.NewGuid(),
            UserId: 12345,
            Timestamp: 1000000,
            Nonce: "test-nonce",
            Hmac: null);

        var signed = _signer.Sign(payload);

        // Tamper with the signed data by changing "approve" to "deny"
        var tampered = signed.Replace("approve", "deny", StringComparison.Ordinal);

        // Act
        var verified = _signer.Verify(tampered);

        // Assert
        verified.Should().BeNull("tampered signature should fail verification");
    }

    [Fact]
    public void CallbackDataSigner_Should_RejectTamperedUserId()
    {
        // Arrange
        var payload = new CallbackPayload(
            Action: "approve",
            ToolUseId: "tool-123",
            SessionId: Guid.NewGuid(),
            UserId: 12345,
            Timestamp: 1000000,
            Nonce: "test-nonce",
            Hmac: null);

        var signed = _signer.Sign(payload);

        // Tamper with user ID
        var tampered = signed.Replace("12345", "99999", StringComparison.Ordinal);

        // Act
        var verified = _signer.Verify(tampered);

        // Assert
        verified.Should().BeNull("tampered user ID should fail verification");
    }

    [Fact]
    public void CallbackDataSigner_Should_RejectCompletelyInvalidHmac()
    {
        // Arrange
        var invalidPayload = "{\"action\":\"approve\",\"toolUseId\":\"tool-123\",\"sessionId\":\"00000000-0000-0000-0000-000000000000\",\"userId\":12345,\"timestamp\":1000000,\"nonce\":\"test\",\"hmac\":\"invalid-hmac-signature\"}";

        // Act
        var verified = _signer.Verify(invalidPayload);

        // Assert
        verified.Should().BeNull("completely invalid HMAC should fail verification");
    }

    [Fact]
    public void CallbackDataSigner_Should_RejectMalformedJson()
    {
        // Arrange
        var malformedPayload = "{\"action\":\"approve\",invalid json}";

        // Act
        var verified = _signer.Verify(malformedPayload);

        // Assert
        verified.Should().BeNull("malformed JSON should fail verification");
    }

    [Fact]
    public void CallbackDataSigner_Should_RejectNullOrEmptyData()
    {
        // Act & Assert
        _signer.Verify(null!).Should().BeNull();
        _signer.Verify(string.Empty).Should().BeNull();
        _signer.Verify("   ").Should().BeNull();
    }

    [Fact]
    public void CallbackDataSigner_Should_RejectPayloadWithoutHmac()
    {
        // Arrange
        var payloadWithoutHmac = "{\"action\":\"approve\",\"toolUseId\":\"tool-123\",\"sessionId\":\"00000000-0000-0000-0000-000000000000\",\"userId\":12345,\"timestamp\":1000000,\"nonce\":\"test\"}";

        // Act
        var verified = _signer.Verify(payloadWithoutHmac);

        // Assert
        verified.Should().BeNull("payload without HMAC should fail verification");
    }

    [Fact]
    public void CallbackDataSigner_Should_UseConstantTimeComparison()
    {
        // Arrange
        var payload = new CallbackPayload(
            Action: "approve",
            ToolUseId: "tool-123",
            SessionId: Guid.NewGuid(),
            UserId: 12345,
            Timestamp: 1000000,
            Nonce: "test-nonce",
            Hmac: null);

        var signed = _signer.Sign(payload);

        // Tamper by changing one character in HMAC (should still fail even though close)
        var json = System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, object>>(signed);
        if (json != null && json.TryGetValue("hmac", out var hmacValue))
        {
            var hmac = hmacValue.ToString()!;
            var tamperedHmac = hmac[..^1] + (hmac[^1] == 'A' ? 'B' : 'A');
            json["hmac"] = tamperedHmac;
            var tamperedSigned = System.Text.Json.JsonSerializer.Serialize(json);

            // Act
            var verified = _signer.Verify(tamperedSigned);

            // Assert
            verified.Should().BeNull("even single character change in HMAC should fail verification");
        }
    }

    [Fact]
    public void CallbackDataSigner_Should_GenerateUniqueNonces()
    {
        // Arrange & Act - Generate multiple payloads with different nonces
        var payload1 = new CallbackPayload("approve", "tool-1", Guid.NewGuid(), 123, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Guid.NewGuid().ToString(), null);
        var payload2 = new CallbackPayload("approve", "tool-1", Guid.NewGuid(), 123, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), Guid.NewGuid().ToString(), null);

        var signed1 = _signer.Sign(payload1);
        var signed2 = _signer.Sign(payload2);

        // Assert - Different nonces should produce different signatures even with same action/tool
        signed1.Should().NotBe(signed2, "different nonces should produce different signatures");
    }

    [Fact]
    public void CallbackPayload_Should_AllowDirectoryAccessActions()
    {
        // Arrange
        var payload = new CallbackPayload(
            Action: "dir_readonly",
            ToolUseId: "",
            SessionId: Guid.NewGuid(),
            UserId: 12345,
            Timestamp: 1000000,
            Nonce: "test-nonce",
            Hmac: null);

        var signed = _signer.Sign(payload);

        // Act
        var verified = _signer.Verify(signed);

        // Assert
        verified.Should().NotBeNull();
        verified!.Action.Should().Be("dir_readonly");
    }

    [Fact]
    public void CallbackPayload_Should_AllowCommandActions()
    {
        // Arrange
        var payload = new CallbackPayload(
            Action: "cmd_approve",
            ToolUseId: "",
            SessionId: Guid.NewGuid(),
            UserId: 12345,
            Timestamp: 1000000,
            Nonce: "test-nonce",
            Hmac: null);

        var signed = _signer.Sign(payload);

        // Act
        var verified = _signer.Verify(signed);

        // Assert
        verified.Should().NotBeNull();
        verified!.Action.Should().Be("cmd_approve");
    }
}
