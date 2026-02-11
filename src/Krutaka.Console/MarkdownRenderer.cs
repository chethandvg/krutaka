using System.Globalization;
using System.Text;
using Markdig;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;
using Spectre.Console;

namespace Krutaka.Console;

/// <summary>
/// Renders Markdown content to Spectre.Console markup.
/// Converts Markdown AST elements to styled console output.
/// </summary>
internal sealed class MarkdownRenderer
{
    private readonly MarkdownPipeline _pipeline;

    /// <summary>
    /// Initializes a new instance of the <see cref="MarkdownRenderer"/> class.
    /// </summary>
    public MarkdownRenderer()
    {
        _pipeline = new MarkdownPipelineBuilder()
            .UseAdvancedExtensions()
            .Build();
    }

    /// <summary>
    /// Renders Markdown text to Spectre.Console.
    /// </summary>
    /// <param name="markdown">The markdown text to render.</param>
    public void Render(string markdown)
    {
        ArgumentNullException.ThrowIfNull(markdown);

        var document = Markdown.Parse(markdown, _pipeline);
        RenderDocument(document);
    }

    /// <summary>
    /// Converts Markdown to Spectre.Console markup string.
    /// </summary>
    /// <param name="markdown">The markdown text to convert.</param>
    /// <returns>Spectre.Console markup string.</returns>
    public string ToMarkup(string markdown)
    {
        ArgumentNullException.ThrowIfNull(markdown);

        var document = Markdown.Parse(markdown, _pipeline);
        var builder = new StringBuilder();
        ConvertDocumentToMarkup(document, builder);
        return builder.ToString();
    }

    private void RenderDocument(MarkdownDocument document)
    {
        foreach (var block in document)
        {
            RenderBlock(block);
        }
    }

    private void ConvertDocumentToMarkup(MarkdownDocument document, StringBuilder builder)
    {
        foreach (var block in document)
        {
            ConvertBlockToMarkup(block, builder);
        }
    }

    private void RenderBlock(Block block)
    {
        switch (block)
        {
            case HeadingBlock heading:
                RenderHeading(heading);
                break;

            case CodeBlock codeBlock:
                RenderCodeBlock(codeBlock);
                break;

            case ParagraphBlock paragraph:
                RenderParagraph(paragraph);
                break;

            case ListBlock list:
                RenderList(list, 0);
                break;

            case QuoteBlock quote:
                RenderQuote(quote);
                break;

            case ThematicBreakBlock:
                AnsiConsole.WriteLine(new string('─', 80));
                AnsiConsole.WriteLine();
                break;

            default:
                // For unknown block types, render as plain text
                RenderGenericBlock(block);
                break;
        }
    }

    private void ConvertBlockToMarkup(Block block, StringBuilder builder)
    {
        switch (block)
        {
            case HeadingBlock heading:
                ConvertHeadingToMarkup(heading, builder);
                break;

            case CodeBlock codeBlock:
                // Code blocks need special handling - return placeholder
                builder.AppendLine(CultureInfo.InvariantCulture, $"[dim]{Markup.Escape(codeBlock.Lines.ToString())}[/]");
                break;

            case ParagraphBlock paragraph:
                ConvertParagraphToMarkup(paragraph, builder);
                builder.AppendLine();
                break;

            case ListBlock list:
                ConvertListToMarkup(list, builder, 0);
                break;

            case QuoteBlock quote:
                ConvertQuoteToMarkup(quote, builder);
                break;

            case ThematicBreakBlock:
                builder.AppendLine(new string('─', 80));
                builder.AppendLine();
                break;

            default:
                builder.AppendLine(Markup.Escape(block.ToString() ?? string.Empty));
                break;
        }
    }

    private void RenderHeading(HeadingBlock heading)
    {
        var prefix = new string('#', heading.Level);
        var content = GetInlineText(heading.Inline);
        AnsiConsole.MarkupLine($"[bold blue]{Markup.Escape(prefix)} {Markup.Escape(content)}[/]");
        AnsiConsole.WriteLine();
    }

    private void ConvertHeadingToMarkup(HeadingBlock heading, StringBuilder builder)
    {
        var prefix = new string('#', heading.Level);
        var content = GetInlineText(heading.Inline);
        builder.AppendLine(CultureInfo.InvariantCulture, $"[bold blue]{Markup.Escape(prefix)} {Markup.Escape(content)}[/]");
        builder.AppendLine();
    }

    private static void RenderCodeBlock(CodeBlock codeBlock)
    {
        var code = codeBlock.Lines.ToString();
        var language = (codeBlock as FencedCodeBlock)?.Info ?? string.Empty;

        var title = string.IsNullOrEmpty(language)
            ? "Code"
            : language;

        var panel = new Panel(Markup.Escape(code))
            .Header($"[dim]{Markup.Escape(title)}[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Grey);

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    private void RenderParagraph(ParagraphBlock paragraph)
    {
        if (paragraph.Inline is not null)
        {
            var markup = ConvertInlineToMarkup(paragraph.Inline);
            AnsiConsole.MarkupLine(markup);
        }

        AnsiConsole.WriteLine();
    }

    private void ConvertParagraphToMarkup(ParagraphBlock paragraph, StringBuilder builder)
    {
        if (paragraph.Inline is not null)
        {
            var markup = ConvertInlineToMarkup(paragraph.Inline);
            builder.AppendLine(markup);
        }
    }

    private void RenderList(ListBlock list, int indentLevel)
    {
        var index = 1;
        foreach (var item in list.OfType<ListItemBlock>())
        {
            var indent = new string(' ', indentLevel * 2);
            var bullet = list.IsOrdered
                ? $"{index.ToString(CultureInfo.InvariantCulture)}."
                : "•";

            AnsiConsole.Markup($"{indent}[dim]{bullet}[/] ");

            foreach (var block in item)
            {
                if (block is ParagraphBlock para && para.Inline is not null)
                {
                    var markup = ConvertInlineToMarkup(para.Inline);
                    AnsiConsole.MarkupLine(markup);
                }
                else if (block is ListBlock nestedList)
                {
                    AnsiConsole.WriteLine();
                    RenderList(nestedList, indentLevel + 1);
                }
            }

            index++;
        }

        AnsiConsole.WriteLine();
    }

    private void ConvertListToMarkup(ListBlock list, StringBuilder builder, int indentLevel)
    {
        var index = 1;
        foreach (var item in list.OfType<ListItemBlock>())
        {
            var indent = new string(' ', indentLevel * 2);
            var bullet = list.IsOrdered
                ? $"{index.ToString(CultureInfo.InvariantCulture)}."
                : "•";

            builder.Append(CultureInfo.InvariantCulture, $"{indent}[dim]{bullet}[/] ");

            foreach (var block in item)
            {
                if (block is ParagraphBlock para && para.Inline is not null)
                {
                    var markup = ConvertInlineToMarkup(para.Inline);
                    builder.AppendLine(markup);
                }
                else if (block is ListBlock nestedList)
                {
                    builder.AppendLine();
                    ConvertListToMarkup(nestedList, builder, indentLevel + 1);
                }
            }

            index++;
        }

        builder.AppendLine();
    }

    private void RenderQuote(QuoteBlock quote)
    {
        foreach (var block in quote.OfType<ParagraphBlock>())
        {
            if (block.Inline is not null)
            {
                var text = GetInlineText(block.Inline);
                AnsiConsole.MarkupLine($"[dim]│[/] [italic]{Markup.Escape(text)}[/]");
            }
        }

        AnsiConsole.WriteLine();
    }

    private static void ConvertQuoteToMarkup(QuoteBlock quote, StringBuilder builder)
    {
        foreach (var block in quote.OfType<ParagraphBlock>())
        {
            if (block.Inline is not null)
            {
                var text = GetInlineTextStatic(block.Inline);
                builder.AppendLine(CultureInfo.InvariantCulture, $"[dim]│[/] [italic]{Markup.Escape(text)}[/]");
            }
        }

        builder.AppendLine();
    }

    private static string GetInlineTextStatic(ContainerInline? inline)
    {
        if (inline is null)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        foreach (var child in inline)
        {
            builder.Append(GetInlineElementTextStatic(child));
        }

        return builder.ToString();
    }

    private static string GetInlineElementTextStatic(Inline inline)
    {
        return inline switch
        {
            LiteralInline literal => literal.Content.ToString(),
            CodeInline code => code.Content,
            EmphasisInline emphasis => GetInlineTextStatic(emphasis),
            LinkInline link => GetInlineTextStatic(link),
            LineBreakInline => " ",
            _ => inline.ToString() ?? string.Empty
        };
    }

    private static void RenderGenericBlock(Block block)
    {
        var text = block.ToString();
        if (!string.IsNullOrWhiteSpace(text))
        {
            AnsiConsole.MarkupLine(Markup.Escape(text));
            AnsiConsole.WriteLine();
        }
    }

    private string ConvertInlineToMarkup(ContainerInline inline)
    {
        var builder = new StringBuilder();

        foreach (var child in inline)
        {
            builder.Append(ConvertInlineElementToMarkup(child));
        }

        return builder.ToString();
    }

    private string ConvertInlineElementToMarkup(Inline inline)
    {
        return inline switch
        {
            LiteralInline literal => Markup.Escape(literal.Content.ToString()),
            CodeInline code => $"[grey]{Markup.Escape(code.Content)}[/]",
            EmphasisInline { DelimiterCount: 1 } emphasis => $"[italic]{ConvertInlineToMarkup(emphasis)}[/]",
            EmphasisInline { DelimiterCount: 2 } emphasis => $"[bold]{ConvertInlineToMarkup(emphasis)}[/]",
            LinkInline link => $"[link={Markup.Escape(link.Url ?? string.Empty)}]{ConvertInlineToMarkup(link)}[/]",
            LineBreakInline => Environment.NewLine,
            _ => Markup.Escape(inline.ToString() ?? string.Empty)
        };
    }

    private string GetInlineText(ContainerInline? inline)
    {
        if (inline is null)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        foreach (var child in inline)
        {
            builder.Append(GetInlineElementText(child));
        }

        return builder.ToString();
    }

    private string GetInlineElementText(Inline inline)
    {
        return inline switch
        {
            LiteralInline literal => literal.Content.ToString(),
            CodeInline code => code.Content,
            EmphasisInline emphasis => GetInlineText(emphasis),
            LinkInline link => GetInlineText(link),
            LineBreakInline => " ",
            _ => inline.ToString() ?? string.Empty
        };
    }
}
