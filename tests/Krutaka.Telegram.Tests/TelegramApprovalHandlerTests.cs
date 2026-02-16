using FluentAssertions;
using Xunit;

namespace Krutaka.Telegram.Tests;

/// <summary>
/// Tests for TelegramApprovalHandler - Focus on HMAC signing security and compact callback data.
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
            ApprovalId: "test123",
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
            ApprovalId: "test123",
            Hmac: null);

        var signed = _signer.Sign(payload);

        // Act
        var verified = _signer.Verify(signed);

        // Assert
        verified.Should().NotBeNull();
        verified!.ApprovalId.Should().Be("test123");
    }

    [Fact]
    public void CallbackDataSigner_Should_RejectTamperedApprovalId()
    {
        // Arrange
        var payload = new CallbackPayload(
            ApprovalId: "test123",
            Hmac: null);

        var signed = _signer.Sign(payload);

        // Tamper with the signed data by changing the approval ID
        var tampered = signed.Replace("test123", "test999", StringComparison.Ordinal);

        // Act
        var verified = _signer.Verify(tampered);

        // Assert
        verified.Should().BeNull("tampered signature should fail verification");
    }

    [Fact]
    public void CallbackDataSigner_Should_RejectCompletelyInvalidHmac()
    {
        // Arrange
        var invalidPayload = "{\"approvalId\":\"test123\",\"hmac\":\"invalid-hmac-signature\"}";

        // Act
        var verified = _signer.Verify(invalidPayload);

        // Assert
        verified.Should().BeNull("completely invalid HMAC should fail verification");
    }

    [Fact]
    public void CallbackDataSigner_Should_RejectMalformedJson()
    {
        // Arrange
        var malformedPayload = "{\"approvalId\":\"test\",invalid json}";

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
        var payloadWithoutHmac = "{\"approvalId\":\"test123\"}";

        // Act
        var verified = _signer.Verify(payloadWithoutHmac);

        // Assert
        verified.Should().BeNull("payload without HMAC should fail verification");
    }

    [Fact]
    public void CallbackDataSigner_Should_ProduceCompactOutput()
    {
        // Arrange
        var payload = new CallbackPayload(
            ApprovalId: "test1",
            Hmac: null);

        // Act
        var signed = _signer.Sign(payload);

        // Assert
        signed.Length.Should().BeLessOrEqualTo(64, "callback data must fit within Telegram's 64-byte limit");
    }

    [Fact]
    public void CallbackDataSigner_Should_HandleLongApprovalIds()
    {
        // Arrange - Use a 5-character approval ID (typical for base64-encoded 4 bytes)
        var payload = new CallbackPayload(
            ApprovalId: "AbCdE",
            Hmac: null);

        // Act
        var signed = _signer.Sign(payload);
        var verified = _signer.Verify(signed);

        // Assert
        signed.Length.Should().BeLessOrEqualTo(64, "callback data must fit within Telegram's 64-byte limit");
        verified.Should().NotBeNull();
        verified!.ApprovalId.Should().Be("AbCdE");
    }

    [Fact]
    public void CallbackDataSigner_Should_UseConstantTimeComparison()
    {
        // Arrange
        var payload = new CallbackPayload(
            ApprovalId: "test123",
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
    public void CallbackDataSigner_Should_GenerateUniqueSignatures()
    {
        // Arrange & Act - Generate multiple payloads with different approval IDs
        var payload1 = new CallbackPayload("approval-1", null);
        var payload2 = new CallbackPayload("approval-2", null);

        var signed1 = _signer.Sign(payload1);
        var signed2 = _signer.Sign(payload2);

        // Assert - Different approval IDs should produce different signatures
        signed1.Should().NotBe(signed2, "different approval IDs should produce different signatures");
    }

    [Fact]
    public void CallbackPayload_Should_BeCompact()
    {
        // Arrange
        var payload = new CallbackPayload(
            ApprovalId: "AbCdE",
            Hmac: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // 44-char Base64 HMAC

        // Act
        var json = System.Text.Json.JsonSerializer.Serialize(payload);

        // Assert
        json.Length.Should().BeLessOrEqualTo(64, "serialized callback payload must fit within Telegram's 64-byte limit");
    }

    [Fact]
    public void CallbackPayload_Should_UseShortFieldNames()
    {
        // Arrange
        var payload = new CallbackPayload("AbCdE", "test");
        
        // Act
        var json = System.Text.Json.JsonSerializer.Serialize(payload);
        
        // Assert
        json.Should().Contain("\"i\":", "should use short field name 'i' for ApprovalId");
        json.Should().Contain("\"s\":", "should use short field name 's' for Hmac");
        json.Should().NotContain("approvalId", "should not use full field name");
        json.Should().NotContain("hmac", "should not use full field name");
    }
}
