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
    /// XML-escapes the content to prevent breaking out of the untrusted_content wrapper.
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

        var trimmed = text.Trim();

        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return string.Empty;
        }

        // XML-escape content to prevent breaking out of the untrusted_content tag
        // This prevents injection attempts like "</untrusted_content>malicious<untrusted_content>"
        var escapedContent = System.Security.SecurityElement.Escape(trimmed);

        // Wrap in untrusted_content tags with source attribution
        return $"<untrusted_content source=\"telegram:user:{userId}\">{escapedContent}</untrusted_content>";
    }

    /// <summary>
    /// Sanitizes file caption by wrapping it in untrusted_content tags with source attribution.
    /// XML-escapes the content to prevent breaking out of the untrusted_content wrapper.
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

        // XML-escape caption content to prevent breaking out of the untrusted_content tag
        var escapedCaption = System.Security.SecurityElement.Escape(trimmed);

        // Wrap in untrusted_content tags with source attribution
        return $"<untrusted_content source=\"telegram:user:{userId}\">{escapedCaption}</untrusted_content>";
    }
}
