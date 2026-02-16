using FluentAssertions;

namespace Krutaka.Telegram.Tests;

public class TelegramInputSanitizerTests
{
    [Fact]
    public void SanitizeMessageText_Should_WrapTextInUntrustedContentTags()
    {
        // Arrange
        var text = "how does authentication work?";
        var userId = 12345678L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeMessageText(text, userId);

        // Assert
        sanitized.Should().Be("<untrusted_content source=\"telegram:user:12345678\">how does authentication work?</untrusted_content>");
    }

    [Fact]
    public void SanitizeMessageText_Should_StripBotMentionSyntax()
    {
        // Arrange
        var text = "/ask@krutaka_bot test message";
        var userId = 12345678L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeMessageText(text, userId);

        // Assert
        sanitized.Should().Be("<untrusted_content source=\"telegram:user:12345678\">/ask test message</untrusted_content>");
    }

    [Fact]
    public void SanitizeMessageText_Should_ReturnEmptyString_ForNullText()
    {
        // Arrange
        string? text = null;
        var userId = 12345678L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeMessageText(text!, userId);

        // Assert
        sanitized.Should().BeEmpty();
    }

    [Fact]
    public void SanitizeMessageText_Should_ReturnEmptyString_ForWhitespaceText()
    {
        // Arrange
        var text = "   ";
        var userId = 12345678L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeMessageText(text, userId);

        // Assert
        sanitized.Should().BeEmpty();
    }

    [Fact]
    public void SanitizeMessageText_Should_IncludeSourceAttribution()
    {
        // Arrange
        var text = "test message";
        var userId = 87654321L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeMessageText(text, userId);

        // Assert
        sanitized.Should().Contain("source=\"telegram:user:87654321\"");
    }

    [Fact]
    public void SanitizeFileCaption_Should_WrapCaptionInUntrustedContentTags()
    {
        // Arrange
        var caption = "Here is the file";
        var userId = 12345678L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeFileCaption(caption, userId);

        // Assert
        sanitized.Should().Be("<untrusted_content source=\"telegram:user:12345678\">Here is the file</untrusted_content>");
    }

    [Fact]
    public void SanitizeFileCaption_Should_ReturnNull_ForNullCaption()
    {
        // Arrange
        string? caption = null;
        var userId = 12345678L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeFileCaption(caption, userId);

        // Assert
        sanitized.Should().BeNull();
    }

    [Fact]
    public void SanitizeFileCaption_Should_ReturnNull_ForEmptyCaption()
    {
        // Arrange
        var caption = string.Empty;
        var userId = 12345678L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeFileCaption(caption, userId);

        // Assert
        sanitized.Should().BeNull();
    }

    [Fact]
    public void SanitizeFileCaption_Should_ReturnNull_ForWhitespaceCaption()
    {
        // Arrange
        var caption = "   ";
        var userId = 12345678L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeFileCaption(caption, userId);

        // Assert
        sanitized.Should().BeNull();
    }

    [Fact]
    public void SanitizeFileCaption_Should_IncludeSourceAttribution()
    {
        // Arrange
        var caption = "test caption";
        var userId = 87654321L;

        // Act
        var sanitized = TelegramInputSanitizer.SanitizeFileCaption(caption, userId);

        // Assert
        sanitized.Should().Contain("source=\"telegram:user:87654321\"");
    }
}
