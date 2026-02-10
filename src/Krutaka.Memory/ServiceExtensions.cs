using Krutaka.Core;
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
        // Note: SessionStore requires runtime parameters (projectPath, sessionId)
        // It should be created via factory pattern or injected directly when needed
        // Registration deferred to composition root (Program.cs) where these values are available
        
        // TODO: Register IMemoryService
        // TODO: Initialize SQLite database
        return services;
    }
}
