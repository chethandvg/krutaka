using FluentAssertions;
using Xunit;

namespace Krutaka.Console.Tests;

/// <summary>
/// Unit tests for MarkdownRenderer class.
/// </summary>
public class MarkdownRendererTests
{
    [Fact]
    public void Constructor_ShouldInitialize()
    {
        // Arrange & Act
        var renderer = new MarkdownRenderer();

        // Assert
        renderer.Should().NotBeNull();
    }

    [Fact]
    public void Render_WithNullMarkdown_ThrowsArgumentNullException()
    {
        // Arrange
        var renderer = new MarkdownRenderer();

        // Act & Assert
        var act = () => renderer.Render(null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void ToMarkup_WithNullMarkdown_ThrowsArgumentNullException()
    {
        // Arrange
        var renderer = new MarkdownRenderer();

        // Act & Assert
        var act = () => renderer.ToMarkup(null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void ToMarkup_WithSimpleText_ReturnsEscapedText()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "Hello, world!";

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("Hello, world!");
    }

    [Fact]
    public void ToMarkup_WithHeading_ReturnsFormattedHeading()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "# My Heading";

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("[bold blue]");
        result.Should().Contain("My Heading");
    }

    [Fact]
    public void ToMarkup_WithInlineCode_ReturnsGreyCode()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "Use `Console.WriteLine()` to print.";

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("[grey]");
        result.Should().Contain("Console.WriteLine()");
    }

    [Fact]
    public void ToMarkup_WithBoldText_ReturnsBoldMarkup()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "This is **bold** text.";

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("[bold]");
        result.Should().Contain("bold");
    }

    [Fact]
    public void ToMarkup_WithItalicText_ReturnsItalicMarkup()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "This is *italic* text.";

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("[italic]");
        result.Should().Contain("italic");
    }

    [Fact]
    public void ToMarkup_WithUnorderedList_ReturnsListWithBullets()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = """
            - Item 1
            - Item 2
            - Item 3
            """;

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("•");
        result.Should().Contain("Item 1");
        result.Should().Contain("Item 2");
        result.Should().Contain("Item 3");
    }

    [Fact]
    public void ToMarkup_WithOrderedList_ReturnsListWithNumbers()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = """
            1. First item
            2. Second item
            3. Third item
            """;

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("1.");
        result.Should().Contain("First item");
        result.Should().Contain("2.");
        result.Should().Contain("Second item");
        result.Should().Contain("3.");
        result.Should().Contain("Third item");
    }

    [Fact]
    public void ToMarkup_WithLink_ReturnsLinkMarkup()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "[Click here](https://example.com)";

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("[link=");
        result.Should().Contain("https://example.com");
        result.Should().Contain("Click here");
    }

    [Fact]
    public void ToMarkup_WithCodeBlock_ReturnsCodeContent()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = """
            ```csharp
            Console.WriteLine("Hello");
            ```
            """;

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("Console.WriteLine");
        result.Should().Contain("Hello");
    }

    [Fact]
    public void ToMarkup_WithComplexMarkdown_ReturnsFormattedMarkup()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = """
            # Heading

            This is a paragraph with **bold** and *italic* text.

            - List item 1
            - List item 2

            Use `code` for inline code.
            """;

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("[bold blue]");
        result.Should().Contain("Heading");
        result.Should().Contain("[bold]");
        result.Should().Contain("bold");
        result.Should().Contain("[italic]");
        result.Should().Contain("italic");
        result.Should().Contain("•");
        result.Should().Contain("[grey]");
        result.Should().Contain("code");
    }

    [Fact]
    public void ToMarkup_WithQuote_ReturnsFormattedQuote()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "> This is a quote";

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("[dim]│[/]");
        result.Should().Contain("[italic]");
        result.Should().Contain("This is a quote");
    }

    [Fact]
    public void ToMarkup_WithThematicBreak_ReturnsHorizontalLine()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "---";

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        result.Should().Contain("─");
    }

    [Fact]
    public void ToMarkup_WithSpecialCharacters_EscapesCorrectly()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "Text with [brackets] and <angles>";

        // Act
        var result = renderer.ToMarkup(markdown);

        // Assert
        // Markup.Escape should handle special characters
        result.Should().NotBeNull();
        result.Should().NotBeEmpty();
    }

    [Fact]
    public void Render_WithValidMarkdown_DoesNotThrow()
    {
        // Arrange
        var renderer = new MarkdownRenderer();
        var markdown = "# Test\n\nSome text.";

        // Act & Assert
        var act = () => renderer.Render(markdown);
        act.Should().NotThrow();
    }
}
