using System.Globalization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Polly;
using Anthropic;
using Krutaka.Core;

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
            var apiKey = configuration["Claude:ApiKey"]
                ?? throw new InvalidOperationException("Claude API key not found in configuration");

            var modelId = configuration["Claude:ModelId"] ?? "claude-4-sonnet-20250514";
            var maxTokens = int.Parse(configuration["Claude:MaxTokens"] ?? "8192", CultureInfo.InvariantCulture);
            var temperature = double.Parse(configuration["Claude:Temperature"] ?? "0.7", CultureInfo.InvariantCulture);

            var logger = sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<ClaudeClientWrapper>>();

            // Create Anthropic client
            var client = new AnthropicClient { ApiKey = apiKey };

            return new ClaudeClientWrapper(client, logger, modelId, maxTokens, temperature);
        });

        // Add HTTP resilience pipeline for Anthropic API calls
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
