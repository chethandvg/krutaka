namespace Krutaka.Telegram;

/// <summary>
/// Sanitizes Telegram user input to prevent prompt injection attacks.
/// Basic implementation in v0.4.0 (Issue #139) — hardening (Unicode normalization,
/// entity stripping, control character removal, homoglyph defense) will be added in Issue #144.
/// </summary>
public static class TelegramInputSanitizer
{
    /// <summary>
    /// Sanitizes message text by wrapping it in untrusted_content tags with source attribution.
    /// Strips bot mention syntax (@botname).
    /// </summary>
    /// <param name="text">The message text to sanitize.</param>
    /// <param name="userId">The Telegram user ID for source attribution.</param>
    /// <returns>
    /// Sanitized text wrapped in untrusted_content tags.
    /// Returns empty string if text is null or whitespace.
    /// </returns>
    public static string SanitizeMessageText(string text, long userId)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        // Strip bot mention syntax (e.g., "@krutaka_bot" or "@KrutakaBot")
        // Pattern: @[a-zA-Z0-9_]+ but preserve the surrounding whitespace
        var sanitized = System.Text.RegularExpressions.Regex.Replace(
            text,
            @"@[a-zA-Z0-9_]+",
            string.Empty,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        // Trim any remaining whitespace
        sanitized = sanitized.Trim();

        if (string.IsNullOrWhiteSpace(sanitized))
        {
            return string.Empty;
        }

        // Wrap in untrusted_content tags with source attribution
        return $"<untrusted_content source=\"telegram:user:{userId}\">{sanitized}</untrusted_content>";
    }

    /// <summary>
    /// Sanitizes file caption by wrapping it in untrusted_content tags with source attribution.
    /// </summary>
    /// <param name="caption">The file caption to sanitize (may be null).</param>
    /// <param name="userId">The Telegram user ID for source attribution.</param>
    /// <returns>
    /// Sanitized caption wrapped in untrusted_content tags, or null if caption is null or empty.
    /// </returns>
    public static string? SanitizeFileCaption(string? caption, long userId)
    {
        if (string.IsNullOrWhiteSpace(caption))
        {
            return null;
        }

        var trimmed = caption.Trim();

        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return null;
        }

        // Wrap in untrusted_content tags with source attribution
        return $"<untrusted_content source=\"telegram:user:{userId}\">{trimmed}</untrusted_content>";
    }
}
