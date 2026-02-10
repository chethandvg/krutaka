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
        // Arrange - generate synthetic key to avoid secret scanning
        // Note: API key in structured property (not message template)
        var testApiKey = "sk-ant-" + new string('a', 95);
        var output = CaptureLogWithRedaction("Initializing with API key: {ApiKey}", testApiKey);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(testApiKey);
    }

    [Fact]
    public void Should_RedactAnthropicApiKeyInProperty()
    {
        // Arrange - generate synthetic key to avoid secret scanning
        var testApiKey = "sk-ant-" + new string('b', 95);
        var output = CaptureLogWithRedaction("Test message", 
            new { ApiKey = testApiKey });

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(testApiKey);
    }

    [Fact]
    public void Should_RedactEnvironmentVariablePatternsInProperty()
    {
        // Arrange
        var secrets = new
        {
            AnthropicKey = "ANTHROPIC_API_KEY=secret123",
            DbPassword = "DATABASE_PASSWORD=pass456",
            AuthToken = "AUTH_TOKEN=token789"
        };
        var output = CaptureLogWithRedaction("Environment variables", secrets);

        // Assert
        output.Should().Contain("ANTHROPIC_API_KEY=***REDACTED***");
        output.Should().Contain("DATABASE_PASSWORD=***REDACTED***");
        output.Should().Contain("AUTH_TOKEN=***REDACTED***");
        output.Should().NotContain("secret123");
        output.Should().NotContain("pass456");
        output.Should().NotContain("token789");
    }

    [Fact]
    public void Should_RedactMultipleApiKeysInProperty()
    {
        // Arrange - generate synthetic keys
        var apiKey1 = "sk-ant-" + new string('1', 95);
        var apiKey2 = "sk-ant-" + new string('2', 95);
        var keys = new { Key1 = apiKey1, Key2 = apiKey2 };
        var output = CaptureLogWithRedaction("Multiple keys", keys);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(apiKey1);
        output.Should().NotContain(apiKey2);
    }

    [Fact]
    public void Should_NotRedactNormalText()
    {
        // Arrange
        var message = "This is a normal log message without secrets";
        var output = CaptureLogWithRedaction(message);

        // Assert
        output.Should().Contain("This is a normal log message without secrets");
        output.Should().NotContain("***REDACTED***");
    }

    [Fact]
    public void Should_RedactApiKeyInNestedProperty()
    {
        // Arrange - generate synthetic key
        var testApiKey = "sk-ant-" + new string('n', 95);
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

        var output = CaptureLogWithRedaction("Nested test", nestedObject);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(testApiKey);
    }

    [Fact]
    public void Should_RedactApiKeyInArrayProperty()
    {
        // Arrange - generate synthetic key
        var testApiKey = "sk-ant-" + new string('a', 95);
        var arrayData = new
        {
            Keys = new[] { testApiKey, "other-value" }
        };

        var output = CaptureLogWithRedaction("Array test", arrayData);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(testApiKey);
        output.Should().Contain("other-value");
    }

    [Fact]
    public void Should_HandleNullPropertiesGracefully()
    {
        // Arrange
        var output = CaptureLogWithRedaction("Test message", 
            new { NullValue = (string?)null });

        // Assert
        output.Should().NotContain("***REDACTED***");
        output.Should().Contain("Test message");
    }

    [Fact]
    public void Should_HandleEmptyStringPropertiesGracefully()
    {
        // Arrange
        var output = CaptureLogWithRedaction("Test message", 
            new { EmptyValue = string.Empty });

        // Assert
        output.Should().NotContain("***REDACTED***");
        output.Should().Contain("Test message");
    }

    [Fact]
    public void Should_RedactMixedSecretTypesInProperties()
    {
        // Arrange - generate synthetic key
        var testApiKey = "sk-ant-" + new string('m', 95);
        var secrets = new
        {
            ApiKey = testApiKey,
            EnvVar = "MY_SECRET=secret123",
            Token = "AUTH_TOKEN=token456"
        };
        var output = CaptureLogWithRedaction("Mixed secrets", secrets);

        // Assert
        output.Should().Contain("***REDACTED***");
        output.Should().NotContain(testApiKey);
        output.Should().NotContain("secret123");
        output.Should().NotContain("token456");
        output.Should().Contain("MY_SECRET=***REDACTED***");
        output.Should().Contain("AUTH_TOKEN=***REDACTED***");
    }

    private static string CaptureLogWithRedaction(
        string messageTemplate, 
        object? propertyValueOrObject = null)
    {
        var logs = new List<string>();
        var logger = new LoggerConfiguration()
            .Enrich.With<LogRedactionEnricher>()
            .WriteTo.Sink(new InMemorySink(logs))
            .CreateLogger();

        if (propertyValueOrObject != null)
        {
            // Check if it's a structured object or a single value
            var type = propertyValueOrObject.GetType();
            if (type.IsValueType || type == typeof(string))
            {
                // Single value - use as message template parameter
                logger.Information(messageTemplate, propertyValueOrObject);
            }
            else
            {
                // Complex object - use as structured property
                logger.Information(messageTemplate + " {@Data}", propertyValueOrObject);
            }
        }
        else
        {
            logger.Information(messageTemplate);
        }

        return string.Join(Environment.NewLine, logs);
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
            using var output = new System.IO.StringWriter(System.Globalization.CultureInfo.InvariantCulture);
            logEvent.RenderMessage(output, System.Globalization.CultureInfo.InvariantCulture);
            _logs.Add(output.ToString());
            
            // Also add property values for comprehensive checking
            foreach (var prop in logEvent.Properties.Where(p => p.Key != "SourceContext"))
            {
                _logs.Add($"{prop.Key}={prop.Value}");
            }
        }
    }
}
