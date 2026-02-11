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
    /// <param name="configureOptions">Optional action to configure memory options.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddMemory(
        this IServiceCollection services,
        Action<MemoryOptions>? configureOptions = null)
    {
        // Register MemoryOptions as singleton
        var options = new MemoryOptions();
        configureOptions?.Invoke(options);
        services.AddSingleton(options);

        // Register SqliteMemoryStore as IMemoryService singleton
        services.AddSingleton<IMemoryService>(sp =>
        {
            var memoryOptions = sp.GetRequiredService<MemoryOptions>();
            var store = new SqliteMemoryStore(memoryOptions);
            
            // Initialize database schema synchronously during DI registration
            // This ensures the database is ready before the service is used
            store.InitializeAsync().GetAwaiter().GetResult();
            
            return store;
        });

        // Note: SessionStore requires runtime parameters (projectPath, sessionId)
        // It should be created via factory pattern or injected directly when needed
        // Registration deferred to composition root (Program.cs) where these values are available
        
        return services;
    }
}

