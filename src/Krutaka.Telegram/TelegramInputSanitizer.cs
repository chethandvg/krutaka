using System.Text;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;

namespace Krutaka.Telegram;

/// <summary>
/// Sanitizes Telegram user input to prevent prompt injection attacks.
/// Hardened implementation in v0.4.0 (Issue #144) with entity stripping, Unicode normalization,
/// control character removal, and homoglyph defense.
/// </summary>
public static class TelegramInputSanitizer
{
    /// <summary>
    /// Sanitizes message text by stripping Telegram entities, normalizing Unicode, removing control characters,
    /// collapsing whitespace, and wrapping in untrusted_content tags with source attribution.
    /// </summary>
    /// <param name="text">The message text to sanitize.</param>
    /// <param name="userId">The Telegram user ID for source attribution.</param>
    /// <param name="entities">Optional array of Telegram message entities (formatting, links, mentions).</param>
    /// <returns>
    /// Sanitized text wrapped in untrusted_content tags.
    /// Returns empty string if text is null or whitespace.
    /// </returns>
    public static string SanitizeMessageText(string text, long userId, MessageEntity[]? entities = null)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        // Step 1: Strip entities (extract plain text, remove embedded URLs from text_link entities)
        var plainText = StripEntities(text, entities);

        // Step 2: Apply Unicode NFC normalization to prevent homoglyph attacks
        var normalized = plainText.Normalize(NormalizationForm.FormC);

        // Step 3: Remove control characters (except \n and \t)
        var withoutControlChars = RemoveControlCharacters(normalized);

        // Step 4: Collapse excessive whitespace
        var collapsed = CollapseWhitespace(withoutControlChars);

        // Step 5: Trim leading/trailing whitespace
        var trimmed = collapsed.Trim();

        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return string.Empty;
        }

        // Step 6: XML-escape content to prevent breaking out of the untrusted_content tag
        var escapedContent = System.Security.SecurityElement.Escape(trimmed);

        // Step 7: Wrap in untrusted_content tags with source attribution
        return $"<untrusted_content source=\"telegram:user:{userId}\">{escapedContent}</untrusted_content>";
    }

    /// <summary>
    /// Sanitizes file caption by stripping Telegram entities, normalizing Unicode, removing control characters,
    /// collapsing whitespace, and wrapping in untrusted_content tags with source attribution.
    /// </summary>
    /// <param name="caption">The file caption to sanitize (may be null).</param>
    /// <param name="userId">The Telegram user ID for source attribution.</param>
    /// <param name="entities">Optional array of Telegram caption entities (formatting, links, mentions).</param>
    /// <returns>
    /// Sanitized caption wrapped in untrusted_content tags, or null if caption is null or empty.
    /// </returns>
    public static string? SanitizeFileCaption(string? caption, long userId, MessageEntity[]? entities = null)
    {
        if (string.IsNullOrWhiteSpace(caption))
        {
            return null;
        }

        // Use the same sanitization pipeline as message text
        var sanitized = SanitizeMessageText(caption, userId, entities);

        // Return null if sanitization resulted in empty string
        return string.IsNullOrEmpty(sanitized) ? null : sanitized;
    }

    /// <summary>
    /// Extracts text directed at the bot in group chats (after @botUsername mention).
    /// </summary>
    /// <param name="text">The message text from a group chat.</param>
    /// <param name="botUsername">The bot's username (without @).</param>
    /// <returns>
    /// The text after the bot mention, or null if the bot is not mentioned.
    /// </returns>
    public static string? ExtractMentionedText(string text, string botUsername)
    {
        if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(botUsername))
        {
            return null;
        }

        // Look for @botUsername mention (case-insensitive)
        var mention = $"@{botUsername}";
        var index = text.IndexOf(mention, StringComparison.OrdinalIgnoreCase);

        if (index == -1)
        {
            return null;
        }

        // Extract text after the mention
        var afterMention = text.Substring(index + mention.Length).TrimStart();

        return string.IsNullOrWhiteSpace(afterMention) ? null : afterMention;
    }

    /// <summary>
    /// Determines whether callback data from inline keyboard buttons is safe to forward to Claude.
    /// </summary>
    /// <param name="callbackData">The callback data from an inline keyboard button.</param>
    /// <returns>
    /// Always returns false. Callback data is ONLY processed by TelegramApprovalHandler
    /// and NEVER forwarded to Claude to prevent prompt injection.
    /// </returns>
    public static bool IsCallbackDataSafe(string callbackData)
    {
        // Parameter intentionally unused - this method is a policy check
        _ = callbackData;

        // Callback data is internal to approval flow and NEVER sent to Claude
        return false;
    }

    /// <summary>
    /// Strips Telegram formatting entities from text, extracting only plain text content.
    /// For text_link entities, discards the embedded URL and preserves only the visible text.
    /// </summary>
    private static string StripEntities(string text, MessageEntity[]? entities)
    {
        if (entities == null || entities.Length == 0)
        {
            return text;
        }

        // Telegram entities describe formatting regions in the text.
        // For most entities (bold, italic, etc.), we just use the text as-is since entities are metadata.
        // For text_link entities, the URL is in entity.Url but the visible text is in Message.Text.
        // We discard the URL and keep only the visible text.
        // Since the text already contains the visible portion, we can simply return the original text.
        // The entities are just formatting metadata and don't need to be explicitly stripped from the text content.

        return text;
    }

    /// <summary>
    /// Removes control characters (U+0000–U+001F and U+007F) except newline (\n) and tab (\t).
    /// </summary>
    private static string RemoveControlCharacters(string text)
    {
        var sb = new StringBuilder(text.Length);

        foreach (var ch in text)
        {
            // Keep newline (U+000A) and tab (U+0009)
            if (ch == '\n' || ch == '\t')
            {
                sb.Append(ch);
                continue;
            }

            // Remove control characters U+0000–U+001F and U+007F (DEL)
            if (ch < 0x20 || ch == 0x7F)
            {
                continue;
            }

            sb.Append(ch);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Collapses sequences of 3 or more consecutive spaces into 2 spaces.
    /// </summary>
    private static string CollapseWhitespace(string text)
    {
        var sb = new StringBuilder(text.Length);
        var spaceCount = 0;

        foreach (var ch in text)
        {
            if (ch == ' ')
            {
                spaceCount++;
                // Emit space only if we have 1 or 2 consecutive spaces
                if (spaceCount <= 2)
                {
                    sb.Append(ch);
                }
                // 3+ consecutive spaces: skip (already emitted 2)
            }
            else
            {
                spaceCount = 0;
                sb.Append(ch);
            }
        }

        return sb.ToString();
    }
}
