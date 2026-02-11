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

        // Register MemoryFileService as singleton
        services.AddSingleton(sp =>
        {
            var krutakaDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".krutaka");
            var memoryFilePath = Path.Combine(krutakaDir, "MEMORY.md");
            return new MemoryFileService(memoryFilePath);
        });

        // Register DailyLogService as singleton
        services.AddSingleton(sp =>
        {
            var krutakaDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".krutaka");
            var logsDirectory = Path.Combine(krutakaDir, "logs");
            var memoryService = sp.GetRequiredService<IMemoryService>();
            return new DailyLogService(logsDirectory, memoryService);
        });

        // Register memory tools (will be registered with ToolRegistry via AddAgentTools pattern)
        services.AddSingleton<ITool>(sp =>
        {
            var memoryFileService = sp.GetRequiredService<MemoryFileService>();
            var memoryService = sp.GetRequiredService<IMemoryService>();

            return new MemoryStoreTool(memoryFileService, memoryService);
        });

        services.AddSingleton<ITool>(sp =>
        {
            var memoryService = sp.GetRequiredService<IMemoryService>();

            return new MemorySearchTool(memoryService);
        });

        // Note: SessionStore requires runtime parameters (projectPath, sessionId)
        // It should be created via factory pattern or injected directly when needed
        // Registration deferred to composition root (Program.cs) where these values are available

        return services;
    }
}

