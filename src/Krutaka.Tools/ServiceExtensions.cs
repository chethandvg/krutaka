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
        services.AddSingleton<IToolRegistry>(registry);

        // Get working directory from options
        var workingDir = options.WorkingDirectory;

        // Register and add all tool implementations
        // Read-only tools (auto-approve)
        var readFileTool = new ReadFileTool(workingDir);
        registry.Register(readFileTool);
        services.AddSingleton<ITool>(readFileTool);

        var listFilesTool = new ListFilesTool(workingDir);
        registry.Register(listFilesTool);
        services.AddSingleton<ITool>(listFilesTool);

        var searchFilesTool = new SearchFilesTool(workingDir);
        registry.Register(searchFilesTool);
        services.AddSingleton<ITool>(searchFilesTool);

        // Write tools (require approval)
        var writeFileTool = new WriteFileTool(workingDir);
        registry.Register(writeFileTool);
        services.AddSingleton<ITool>(writeFileTool);

        var editFileTool = new EditFileTool(workingDir);
        registry.Register(editFileTool);
        services.AddSingleton<ITool>(editFileTool);

        // Register a factory for RunCommandTool since it needs ISecurityPolicy from DI
        services.AddSingleton<ITool>(sp =>
        {
            var securityPolicy = sp.GetRequiredService<ISecurityPolicy>();
            var runCommandTool = new RunCommandTool(workingDir, securityPolicy);
            registry.Register(runCommandTool);
            return runCommandTool;
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
