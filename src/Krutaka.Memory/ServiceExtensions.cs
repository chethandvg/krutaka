using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Memory;

/// <summary>
/// Extension methods for registering memory services.
/// </summary>
public static class ServiceExtensions
{
    /// <summary>
    /// Adds memory and persistence services to the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddMemory(this IServiceCollection services)
    {
        // TODO: Register IMemoryService
        // TODO: Register ISessionStore
        // TODO: Initialize SQLite database
        return services;
    }
}
