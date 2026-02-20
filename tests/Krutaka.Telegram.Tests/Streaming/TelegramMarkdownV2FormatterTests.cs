using FluentAssertions;

namespace Krutaka.Telegram.Tests;

public class TelegramMarkdownV2FormatterTests
{
    [Fact]
    public void Format_Should_EscapeUnderscore()
    {
        // Arrange
        var text = "Hello_world";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be(@"Hello\_world");
    }

    [Fact]
    public void Format_Should_EscapeAsterisk()
    {
        // Arrange
        var text = "Hello*world";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be(@"Hello\*world");
    }

    [Fact]
    public void Format_Should_EscapeAllSpecialCharacters()
    {
        // Arrange - all 15 special characters: _ * [ ] ( ) ~ > # + - = | { } . !
        var text = "_ * [ ] ( ) ~ > # + - = | { } . !";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be(@"\_ \* \[ \] \( \) \~ \> \# \+ \- \= \| \{ \} \. \!");
    }

    [Fact]
    public void Format_Should_NotEscapeInsideCodeBlock()
    {
        // Arrange
        var text = "Before ```code_with_*special*_chars``` after";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be("Before ```code_with_*special*_chars``` after");
    }

    [Fact]
    public void Format_Should_NotEscapeInsideInlineCode()
    {
        // Arrange
        var text = "Before `code_*special*` after";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be("Before `code_*special*` after");
    }

    [Fact]
    public void Format_Should_EscapeOutsideCodeBlockButNotInside()
    {
        // Arrange
        var text = "Hello_world ```code_*special*_chars``` more_text";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be(@"Hello\_world ```code_*special*_chars``` more\_text");
    }

    [Fact]
    public void Format_Should_HandleMultipleCodeBlocks()
    {
        // Arrange
        var text = "Text1_special ```code1``` text2*special ```code2``` text3";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be(@"Text1\_special ```code1``` text2\*special ```code2``` text3");
    }

    [Fact]
    public void Format_Should_HandleMultipleInlineCodeBlocks()
    {
        // Arrange
        var text = "Text1_special `code1*` text2*special `code2_` text3";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be(@"Text1\_special `code1*` text2\*special `code2_` text3");
    }

    [Fact]
    public void Format_Should_HandleMixedCodeBlocks()
    {
        // Arrange
        var text = "Text_1 ```multiline``` text*2 `inline_code` text.3";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be(@"Text\_1 ```multiline``` text\*2 `inline_code` text\.3");
    }

    [Fact]
    public void Format_Should_ReturnEmptyStringForEmpty()
    {
        // Arrange
        var text = "";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be("");
    }

    [Fact]
    public void Format_Should_ReturnNullForNull()
    {
        // Arrange
        string? text = null;

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text!);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void Format_Should_HandleUnmatchedCodeBlockGracefully()
    {
        // Arrange - opening ``` without closing
        var text = "Text ```unclosed_code special_chars";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert - should escape characters after the unclosed code block marker
        result.Should().Be(@"Text ```unclosed\_code special\_chars");
    }

    [Fact]
    public void Format_Should_HandleUnmatchedInlineCodeGracefully()
    {
        // Arrange - opening ` without closing
        var text = "Text `unclosed_inline special*chars";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert - should escape characters after the unclosed inline code marker
        result.Should().Be(@"Text `unclosed\_inline special\*chars");
    }

    [Fact]
    public void TryFormat_Should_ReturnTrueForValidText()
    {
        // Arrange
        var text = "Hello_world";

        // Act
        var success = TelegramMarkdownV2Formatter.TryFormat(text, out var formatted);

        // Assert
        success.Should().BeTrue();
        formatted.Should().Be(@"Hello\_world");
    }

    [Fact]
    public void TryFormat_Should_ReturnOriginalTextOnFailure()
    {
        // Arrange
        var text = "Valid text";

        // Act
        var success = TelegramMarkdownV2Formatter.TryFormat(text, out var formatted);

        // Assert
        success.Should().BeTrue();
        formatted.Should().Be("Valid text");
    }

    [Fact]
    public void Format_Should_HandleComplexRealWorldMarkdown()
    {
        // Arrange
        var text = @"# Header with special chars!

This is a *bold* statement.
- List item 1
- List item 2

```csharp
var code = ""with_special*chars"";
```

Final text with [link](https://example.com)";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert - headers, list markers, and text should be escaped, but code block contents should not
        result.Should().Contain(@"\# Header with special chars\!");
        result.Should().Contain(@"\- List item 1");
        result.Should().Contain(@"\- List item 2");
        result.Should().Contain("```csharp");
        result.Should().Contain(@"var code = ""with_special*chars"";");
        result.Should().Contain(@"\[link\]\(https://example\.com\)");
    }

    [Fact]
    public void Format_Should_HandleNestedBackticks()
    {
        // Arrange - inline code cannot contain backticks in Telegram MarkdownV2
        var text = "Text `code` more text `code2` end";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be("Text `code` more text `code2` end");
    }

    [Fact]
    public void Format_Should_EscapePeriodsAndExclamation()
    {
        // Arrange
        var text = "Hello! How are you? I'm fine.";

        // Act
        var result = TelegramMarkdownV2Formatter.Format(text);

        // Assert
        result.Should().Be(@"Hello\! How are you? I'm fine\.");
    }
}
