using System.Text.RegularExpressions;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace Krutaka.Console.Logging;

/// <summary>
/// Serilog enricher that redacts sensitive information from log events.
/// Scrubs API keys, secrets, and tokens to prevent credential leakage
/// in both structured properties and message template text.
/// </summary>
public sealed partial class LogRedactionEnricher : ILogEventEnricher
{
    private const string RedactedPlaceholder = "***REDACTED***";
    private static readonly MessageTemplateParser TemplateParser = new();

    // Regex patterns for sensitive data
    [GeneratedRegex(@"sk-ant-[a-zA-Z0-9_-]{95,}")]
    private static partial Regex AnthropicApiKeyPattern();

    [GeneratedRegex(@"([a-zA-Z0-9_]+_(KEY|SECRET|TOKEN|PASSWORD))=([^\s;,]+)", RegexOptions.IgnoreCase)]
    private static partial Regex EnvironmentVariablePattern();

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(propertyFactory);

        // Redact all structured properties
        foreach (var property in logEvent.Properties.ToList())
        {
            var redactedValue = RedactProperty(property.Value);
            if (redactedValue != property.Value)
            {
                logEvent.AddOrUpdateProperty(
                    propertyFactory.CreateProperty(property.Key, redactedValue));
            }
        }

        // Check the message template text itself for sensitive data.
        // If found, replace the MessageTemplate by setting the backing field directly,
        // ensuring all sinks (console, file, JSON) render the redacted version.
        // Note: This uses reflection on the compiler-generated backing field, which is
        // fragile but necessary since Serilog's MessageTemplate property is read-only.
        // The Serilog version is pinned in Directory.Packages.props to mitigate breakage.
        var templateText = logEvent.MessageTemplate.Text;
        var redactedTemplate = RedactSensitiveData(templateText);
        if (templateText != redactedTemplate)
        {
            var parsedTemplate = TemplateParser.Parse(redactedTemplate);
            var backingField = typeof(LogEvent).GetField(
                "<MessageTemplate>k__BackingField",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

            if (backingField != null)
            {
                backingField.SetValue(logEvent, parsedTemplate);
            }
            else
            {
                // Fallback: add a RedactedMessage property so the secret is at least
                // available in redacted form, even if the original template still renders.
                logEvent.AddOrUpdateProperty(
                    propertyFactory.CreateProperty("RedactedMessage", redactedTemplate));
            }
        }
    }

    private static LogEventPropertyValue RedactProperty(LogEventPropertyValue value)
    {
        return value switch
        {
            ScalarValue scalar when scalar.Value is string stringValue =>
                new ScalarValue(RedactSensitiveData(stringValue)),

            StructureValue structure =>
                new StructureValue(
                    structure.Properties.Select(p =>
                        new LogEventProperty(p.Name, RedactProperty(p.Value))),
                    structure.TypeTag),

            SequenceValue sequence =>
                new SequenceValue(
                    sequence.Elements.Select(RedactProperty)),

            DictionaryValue dictionary =>
                new DictionaryValue(
                    dictionary.Elements.Select(kvp =>
                    {
                        var redactedKey = kvp.Key.Value is string keyString
                            ? new ScalarValue(RedactSensitiveData(keyString))
                            : kvp.Key;

                        var redactedValue = RedactProperty(kvp.Value);

                        return new KeyValuePair<ScalarValue, LogEventPropertyValue>(redactedKey, redactedValue);
                    })),

            _ => value
        };
    }

    private static string RedactSensitiveData(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        // Redact Anthropic API keys (sk-ant-...)
        var result = AnthropicApiKeyPattern().Replace(input, RedactedPlaceholder);

        // Redact environment variable patterns (KEY=value, SECRET=value, etc.)
        result = EnvironmentVariablePattern().Replace(
            result,
            match => $"{match.Groups[1].Value}={RedactedPlaceholder}");

        return result;
    }
}
