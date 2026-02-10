using FluentAssertions;
using Krutaka.Console.Logging;
using Serilog;
using Serilog.Events;

namespace Krutaka.Console.Tests;

public class LogRedactionEnricherTests
{
    [Fact]
    public void Should_RedactAnthropicApiKeyInMessage()
    {
        // Arrange
        var testApiKey = "sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk";
        var message = $"Initializing with API key: {testApiKey}";
        var (logEvent, output) = CaptureLogWithRedaction(message);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain("sk-ant-");
        output.Should().NotContain(testApiKey);
    }

    [Fact]
    public void Should_RedactAnthropicApiKeyInProperty()
    {
        // Arrange
        var testApiKey = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrst";
        var (logEvent, output) = CaptureLogWithRedaction("Test message", 
            new { ApiKey = testApiKey });

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain("sk-ant-");
        output.Should().NotContain(testApiKey);
    }

    [Fact]
    public void Should_RedactEnvironmentVariablePatternsInMessage()
    {
        // Arrange
        var message = "Environment: ANTHROPIC_API_KEY=secret123, DATABASE_PASSWORD=pass456, AUTH_TOKEN=token789";
        var (logEvent, output) = CaptureLogWithRedaction(message);

        // Assert
        output.Should().Contain("ANTHROPIC_API_KEY=***REDACTED***");
        output.Should().Contain("DATABASE_PASSWORD=***REDACTED***");
        output.Should().Contain("AUTH_TOKEN=***REDACTED***");
        output.Should().NotContain("secret123");
        output.Should().NotContain("pass456");
        output.Should().NotContain("token789");
    }

    [Fact]
    public void Should_RedactMultipleApiKeysInSameMessage()
    {
        // Arrange
        var apiKey1 = "sk-ant-api03-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        var apiKey2 = "sk-ant-api03-2222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";
        var message = $"Keys: {apiKey1} and {apiKey2}";
        var (logEvent, output) = CaptureLogWithRedaction(message);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(apiKey1);
        output.Should().NotContain(apiKey2);
        var redactedCount = System.Text.RegularExpressions.Regex.Matches(output, @"\*\*\*REDACTED\*\*\*").Count;
        redactedCount.Should().BeGreaterOrEqualTo(2);
    }

    [Fact]
    public void Should_NotRedactNormalText()
    {
        // Arrange
        var message = "This is a normal log message without secrets";
        var (logEvent, output) = CaptureLogWithRedaction(message);

        // Assert
        output.Should().Contain("This is a normal log message without secrets");
        output.Should().NotContain("***REDACTED***");
    }

    [Fact]
    public void Should_RedactApiKeyInNestedProperty()
    {
        // Arrange
        var testApiKey = "sk-ant-api03-nested999999999999999999999999999999999999999999999999999999999999999999999999999999999999999";
        var nestedObject = new
        {
            Config = new
            {
                Credentials = new
                {
                    ApiKey = testApiKey
                }
            }
        };

        var (logEvent, output) = CaptureLogWithRedaction("Nested test", nestedObject);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(testApiKey);
    }

    [Fact]
    public void Should_RedactApiKeyInArrayProperty()
    {
        // Arrange
        var testApiKey = "sk-ant-api03-array88888888888888888888888888888888888888888888888888888888888888888888888888888888888888888";
        var arrayData = new
        {
            Keys = new[] { testApiKey, "other-value" }
        };

        var (logEvent, output) = CaptureLogWithRedaction("Array test", arrayData);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(testApiKey);
        output.Should().Contain("other-value");
    }

    [Fact]
    public void Should_HandleNullPropertiesGracefully()
    {
        // Arrange
        var (logEvent, output) = CaptureLogWithRedaction("Test message", 
            new { NullValue = (string?)null });

        // Assert
        output.Should().NotContain("***REDACTED***");
        output.Should().Contain("Test message");
    }

    [Fact]
    public void Should_HandleEmptyStringPropertiesGracefully()
    {
        // Arrange
        var (logEvent, output) = CaptureLogWithRedaction("Test message", 
            new { EmptyValue = string.Empty });

        // Assert
        output.Should().NotContain("***REDACTED***");
        output.Should().Contain("Test message");
    }

    [Fact]
    public void Should_RedactMixedSecretTypes()
    {
        // Arrange
        var testApiKey = "sk-ant-api03-mixed77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777";
        var message = $"API: {testApiKey}, Env: MY_SECRET=secret123, Token: AUTH_TOKEN=token456";
        var (logEvent, output) = CaptureLogWithRedaction(message);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(testApiKey);
        output.Should().NotContain("secret123");
        output.Should().NotContain("token456");
        output.Should().Contain("MY_SECRET=***REDACTED***");
        output.Should().Contain("AUTH_TOKEN=***REDACTED***");
    }

    private static (LogEvent logEvent, string output) CaptureLogWithRedaction(
        string message, 
        object? properties = null)
    {
        var logs = new List<string>();
        var logger = new LoggerConfiguration()
            .Enrich.With<LogRedactionEnricher>()
            .WriteTo.Sink(new InMemorySink(logs))
            .CreateLogger();

        if (properties != null)
        {
            logger.Information(message + " {@Properties}", properties);
        }
        else
        {
            logger.Information(message);
        }

        var output = string.Join(Environment.NewLine, logs);
        return (null!, output);
    }

    private class InMemorySink : Serilog.Core.ILogEventSink
    {
        private readonly List<string> _logs;

        public InMemorySink(List<string> logs)
        {
            _logs = logs;
        }

        public void Emit(LogEvent logEvent)
        {
            // Check if message was redacted (enricher adds OriginalMessageTemplate property)
            if (logEvent.Properties.ContainsKey("OriginalMessageTemplate"))
            {
                // Use the redacted MessageTemplate property value
                if (logEvent.Properties.TryGetValue("MessageTemplate", out var redactedTemplate))
                {
                    _logs.Add(redactedTemplate.ToString().Trim('"'));
                }
            }
            else
            {
                // No redaction needed, render normally
                using var output = new System.IO.StringWriter(System.Globalization.CultureInfo.InvariantCulture);
                logEvent.RenderMessage(output, System.Globalization.CultureInfo.InvariantCulture);
                _logs.Add(output.ToString());
            }
            
            // Also add all properties for comprehensive checking
            foreach (var prop in logEvent.Properties)
            {
                if (prop.Key != "MessageTemplate" && prop.Key != "OriginalMessageTemplate")
                {
                    _logs.Add($"{prop.Key}={prop.Value}");
                }
            }
        }
    }
}
