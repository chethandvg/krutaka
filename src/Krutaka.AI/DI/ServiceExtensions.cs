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
            // Get API key from secure credential store only — never fall back to configuration/environment
            var secretsProvider = sp.GetRequiredService<ISecretsProvider>();
            var apiKey = secretsProvider.GetSecret("Claude:ApiKey")
                ?? throw new InvalidOperationException(
                    "Claude API key not found in secure credential store. " +
                    "Please run the setup wizard to configure your Anthropic API key.");

            var modelId = configuration["Claude:ModelId"] ?? "claude-4-sonnet-20250514";
            var maxTokens = int.Parse(configuration["Claude:MaxTokens"] ?? "8192", CultureInfo.InvariantCulture);
            var temperature = double.Parse(configuration["Claude:Temperature"] ?? "0.7", CultureInfo.InvariantCulture);

            // Read retry configuration from Agent section
            var retryMaxAttempts = int.Parse(configuration["Agent:RetryMaxAttempts"] ?? "3", CultureInfo.InvariantCulture);
            var retryInitialDelayMs = int.Parse(configuration["Agent:RetryInitialDelayMs"] ?? "1000", CultureInfo.InvariantCulture);
            var retryMaxDelayMs = int.Parse(configuration["Agent:RetryMaxDelayMs"] ?? "30000", CultureInfo.InvariantCulture);

            var logger = sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<ClaudeClientWrapper>>();

            // Create Anthropic client with SDK retries DISABLED
            // We use ClaudeClientWrapper's retry logic for full control over rate limit handling
            // Setting MaxRetries = 0 prevents multiplicative retries (SDK retries × wrapper retries)
            var client = new AnthropicClient
            {
                ApiKey = apiKey,
                MaxRetries = 0,  // Disable SDK retries - use wrapper retry logic only
                Timeout = TimeSpan.FromSeconds(120)
            };

            return new ClaudeClientWrapper(
                client, 
                logger, 
                modelId, 
                maxTokens, 
                temperature,
                retryMaxAttempts,
                retryInitialDelayMs,
                retryMaxDelayMs);
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
                // IMPORTANT: Polly requires SamplingDuration >= 2 * AttemptTimeout to avoid configuration errors
                // SamplingDuration: Time window for collecting failure rate samples (300s)
                // AttemptTimeout: Maximum time allowed per attempt (120s)
                // Constraint: 300s >= 2 * 120s = 240s ✓
                // TODO: Review these timeouts if Polly pipeline is actually used in production
                options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(300);
                options.CircuitBreaker.MinimumThroughput = 5;
                options.CircuitBreaker.BreakDuration = TimeSpan.FromSeconds(30);

                // Request timeout
                options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(120);
                options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(300);
            });

        return services;
    }
}
