using Microsoft.Extensions.DependencyInjection;
using Krutaka.Core;

namespace Krutaka.Skills;

/// <summary>
/// Extension methods for registering skill services.
/// </summary>
public static class ServiceExtensions
{
    /// <summary>
    /// Adds skill services to the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional configuration action for skill options.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSkills(
        this IServiceCollection services,
        Action<SkillOptions>? configure = null)
    {
        // Configure options
        var options = new SkillOptions();
        
        // Always start with default directories so callers can extend/override them
        options.AddDefaultDirectories();

        if (configure is not null)
        {
            configure(options);
        }

        // Register SkillLoader as singleton
        services.AddSingleton<SkillLoader>();

        // Register SkillRegistry as singleton with configured directories
        services.AddSingleton<SkillRegistry>(sp =>
        {
            var loader = sp.GetRequiredService<SkillLoader>();
            var registry = new SkillRegistry(loader, options.SkillDirectories);
            
            // Pre-load metadata synchronously (blocking is acceptable during startup)
            // In production, this could be done asynchronously in a background service
            registry.LoadMetadataAsync().GetAwaiter().GetResult();
            
            return registry;
        });

        // Expose the same singleton instance via ISkillRegistry
        services.AddSingleton<ISkillRegistry>(sp => sp.GetRequiredService<SkillRegistry>());

        return services;
    }
}
