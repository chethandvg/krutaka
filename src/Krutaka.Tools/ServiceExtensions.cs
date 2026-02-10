using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Tools;

/// <summary>
/// Extension methods for registering tool services.
/// </summary>
public static class ServiceExtensions
{
    /// <summary>
    /// Adds tool services to the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddTools(this IServiceCollection services)
    {
        // TODO: Register IToolRegistry
        // TODO: Register tool implementations
        // TODO: Register ISecurityPolicy
        return services;
    }
}
