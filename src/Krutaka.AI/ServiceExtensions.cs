using System.Globalization;
using Anthropic;
using Krutaka.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Polly;

namespace Krutaka.AI;

/// <summary>
/// Extension methods for registering AI services.
/// </summary>
public static class ServiceExtensions
{
    /// <summary>
    /// Adds Claude AI client services to the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddClaudeAI(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Register IClaudeClient implementation
        services.AddSingleton<IClaudeClient>(sp =>
        {
            // Get API key from secure credential store
            var secretsProvider = sp.GetService<ISecretsProvider>();
            string apiKey;

            if (secretsProvider != null)
            {
                apiKey = secretsProvider.GetSecret("Claude:ApiKey")
                    ?? throw new InvalidOperationException(
                        "Claude API key not found in secure credential store. " +
                        "Please run the setup wizard to configure your Anthropic API key.");
            }
            else
            {
                // Fallback to configuration for testing/development
                apiKey = configuration["Claude:ApiKey"]
                    ?? throw new InvalidOperationException(
                        "Claude API key not found. Please configure ISecretsProvider or set Claude:ApiKey in configuration.");
            }

            var modelId = configuration["Claude:ModelId"] ?? "claude-4-sonnet-20250514";
            var maxTokens = int.Parse(configuration["Claude:MaxTokens"] ?? "8192", CultureInfo.InvariantCulture);
            var temperature = double.Parse(configuration["Claude:Temperature"] ?? "0.7", CultureInfo.InvariantCulture);

            var logger = sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<ClaudeClientWrapper>>();

            // Create Anthropic client with retry configuration
            // Note: The SDK has built-in retry logic (2 retries by default)
            // We configure it to use 3 retries and 120s timeout
            var client = new AnthropicClient
            {
                ApiKey = apiKey,
                MaxRetries = 3,
                Timeout = TimeSpan.FromSeconds(120)
            };

            return new ClaudeClientWrapper(client, logger, modelId, maxTokens, temperature);
        });

        // Configure HTTP resilience pipeline for general use
        // Note: AnthropicClient has its own internal HttpClient with built-in retry logic
        // This configuration is provided for potential future extensibility
        services.AddHttpClient("AnthropicAPI")
            .AddStandardResilienceHandler(options =>
            {
                // Exponential backoff retry for 5xx and timeouts
                options.Retry.MaxRetryAttempts = 3;
                options.Retry.BackoffType = DelayBackoffType.Exponential;
                options.Retry.UseJitter = true;

                // Circuit breaker for sustained failures
                options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(30);
                options.CircuitBreaker.MinimumThroughput = 5;
                options.CircuitBreaker.BreakDuration = TimeSpan.FromSeconds(30);

                // Request timeout
                options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(120);
                options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(300);
            });

        return services;
    }
}
