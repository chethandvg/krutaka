using Microsoft.Extensions.DependencyInjection;

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
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddClaudeAI(this IServiceCollection services)
    {
        // TODO: Register IClaudeClient implementation
        // TODO: Add HTTP resilience policies
        return services;
    }
}
