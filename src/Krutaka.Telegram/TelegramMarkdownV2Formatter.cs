using System.Text;

namespace Krutaka.Telegram;

/// <summary>
/// Static helper for formatting text as Telegram MarkdownV2.
/// </summary>
public static partial class TelegramMarkdownV2Formatter
{
    // MarkdownV2 special characters that need escaping outside of code blocks:
    // _ * [ ] ( ) ~ > # + - = | { } . !
    private static readonly char[] SpecialChars = ['_', '*', '[', ']', '(', ')', '~', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'];

    /// <summary>
    /// Converts text to Telegram MarkdownV2 format.
    /// Escapes special characters outside of code blocks.
    /// </summary>
    /// <param name="text">The text to format. Can be null or empty.</param>
    /// <returns>The MarkdownV2-formatted text, or the original text if null/empty/formatting fails.</returns>
    public static string? Format(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text;
        }

        try
        {
            return FormatInternal(text);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IndexOutOfRangeException)
        {
            // Graceful fallback: return plain text if formatting fails
            return text;
        }
    }

    private static string FormatInternal(string text)
    {
        var result = new StringBuilder(text.Length * 2);
        var i = 0;

        while (i < text.Length)
        {
            // Check for code blocks (triple backtick)
            if (i + 2 < text.Length && text[i] == '`' && text[i + 1] == '`' && text[i + 2] == '`')
            {
                // Find the closing triple backtick
                var closeIndex = text.IndexOf("```", i + 3, StringComparison.Ordinal);
                if (closeIndex != -1)
                {
                    // Copy the entire code block without escaping its contents
                    var codeBlockLength = closeIndex + 3 - i;
                    result.Append(text.AsSpan(i, codeBlockLength));
                    i = closeIndex + 3;
                    continue;
                }
            }

            // Check for inline code (single backtick)
            if (text[i] == '`')
            {
                // Find the closing backtick
                var closeIndex = text.IndexOf('`', i + 1);
                if (closeIndex != -1)
                {
                    // Copy the inline code without escaping its contents
                    var inlineCodeLength = closeIndex + 1 - i;
                    result.Append(text.AsSpan(i, inlineCodeLength));
                    i = closeIndex + 1;
                    continue;
                }
            }

            // Escape special characters
            if (Array.IndexOf(SpecialChars, text[i]) >= 0)
            {
                result.Append('\\');
            }

            result.Append(text[i]);
            i++;
        }

        return result.ToString();
    }

    /// <summary>
    /// Attempts to format text as MarkdownV2, returning plain text if formatting fails.
    /// </summary>
    /// <param name="text">The text to format. Can be null or empty.</param>
    /// <param name="formatted">The formatted text, or the original text if formatting failed.</param>
    /// <returns>True if formatting succeeded, false if fallback to plain text.</returns>
    public static bool TryFormat(string? text, out string? formatted)
    {
        if (string.IsNullOrEmpty(text))
        {
            formatted = text;
            return true;
        }

        try
        {
            formatted = FormatInternal(text);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IndexOutOfRangeException)
        {
            formatted = text;
            return false;
        }
    }
}
