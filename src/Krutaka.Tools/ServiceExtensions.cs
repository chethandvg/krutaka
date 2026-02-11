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

        // Register and add all tool implementations using factories to resolve IFileOperations
        // Read-only tools (auto-approve)
        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var readFileTool = new ReadFileTool(workingDir, fileOperations);
            registry.Register(readFileTool);
            return readFileTool;
        });

        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var listFilesTool = new ListFilesTool(workingDir, fileOperations);
            registry.Register(listFilesTool);
            return listFilesTool;
        });

        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var searchFilesTool = new SearchFilesTool(workingDir, fileOperations);
            registry.Register(searchFilesTool);
            return searchFilesTool;
        });

        // Write tools (require approval)
        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var writeFileTool = new WriteFileTool(workingDir, fileOperations);
            registry.Register(writeFileTool);
            return writeFileTool;
        });

        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var editFileTool = new EditFileTool(workingDir, fileOperations);
            registry.Register(editFileTool);
            return editFileTool;
        });

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
