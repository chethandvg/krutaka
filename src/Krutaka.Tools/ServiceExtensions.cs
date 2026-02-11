using Krutaka.Core;
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
    /// <param name="configureOptions">Optional action to configure tool options.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddAgentTools(
        this IServiceCollection services,
        Action<ToolOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Configure options
        var options = new ToolOptions();
        configureOptions?.Invoke(options);

        // Register options as singleton
        services.AddSingleton(options);

        // Register file operations service (singleton - will be resolved with IAuditLogger if available)
        services.AddSingleton<IFileOperations>(sp =>
        {
            var auditLogger = sp.GetService<IAuditLogger>();
            return new SafeFileOperations(auditLogger);
        });

        // Register security policy (singleton - will be resolved with IAuditLogger if available)
        services.AddSingleton<ISecurityPolicy>(sp =>
        {
            var auditLogger = sp.GetService<IAuditLogger>();
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            return new CommandPolicy(fileOperations, auditLogger);
        });

        // Register tool registry (singleton - holds registered tools)
        var registry = new ToolRegistry();

        // Get working directory from options
        var workingDir = options.WorkingDirectory;

        // Register and add all tool implementations using factories to resolve IFileOperations
        // Read-only tools (auto-approve)
        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            return new ReadFileTool(workingDir, fileOperations);
        });

        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            return new ListFilesTool(workingDir, fileOperations);
        });

        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            return new SearchFilesTool(workingDir, fileOperations);
        });

        // Write tools (require approval)
        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            return new WriteFileTool(workingDir, fileOperations);
        });

        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            return new EditFileTool(workingDir, fileOperations);
        });

        // Command execution tool (always requires approval)
        services.AddSingleton<ITool>(sp =>
        {
            var securityPolicy = sp.GetRequiredService<ISecurityPolicy>();
            return new RunCommandTool(workingDir, securityPolicy, options.CommandTimeoutSeconds);
        });

        // Register the tool registry with a factory that resolves and registers all tools
        // Tools are added to the registry when IToolRegistry is first resolved from the DI container
        services.AddSingleton<IToolRegistry>(sp =>
        {
            var tools = sp.GetServices<ITool>();
            foreach (var tool in tools)
            {
                registry.Register(tool);
            }

            return registry;
        });

        return services;
    }

    /// <summary>
    /// Legacy method for backward compatibility.
    /// Use <see cref="AddAgentTools"/> instead.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    [Obsolete("Use AddAgentTools instead. This method will be removed in a future version.")]
    public static IServiceCollection AddTools(this IServiceCollection services)
    {
        return AddAgentTools(services);
    }
}
