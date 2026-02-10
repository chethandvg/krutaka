using Microsoft.Extensions.DependencyInjection;

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
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddSkills(this IServiceCollection services)
    {
        // TODO: Register SkillRegistry
        // TODO: Register SkillLoader
        return services;
    }
}
