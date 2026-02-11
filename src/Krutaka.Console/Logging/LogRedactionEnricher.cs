using System.Text.RegularExpressions;
using Serilog.Core;
using Serilog.Events;

namespace Krutaka.Console.Logging;

/// <summary>
/// Serilog enricher that redacts sensitive information from log events.
/// Scrubs API keys, secrets, and tokens to prevent credential leakage.
/// </summary>
public sealed partial class LogRedactionEnricher : ILogEventEnricher
{
    private const string RedactedPlaceholder = "***REDACTED***";

    // Regex patterns for sensitive data
    [GeneratedRegex(@"sk-ant-[a-zA-Z0-9_-]{95,}")]
    private static partial Regex AnthropicApiKeyPattern();

    [GeneratedRegex(@"([a-zA-Z0-9_]+_(KEY|SECRET|TOKEN|PASSWORD))=([^\s;,]+)", RegexOptions.IgnoreCase)]
    private static partial Regex EnvironmentVariablePattern();

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        ArgumentNullException.ThrowIfNull(propertyFactory);

        // Redact all properties
        foreach (var property in logEvent.Properties.ToList())
        {
            var redactedValue = RedactProperty(property.Value);
            if (redactedValue != property.Value)
            {
                logEvent.AddOrUpdateProperty(
                    propertyFactory.CreateProperty(property.Key, redactedValue));
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
