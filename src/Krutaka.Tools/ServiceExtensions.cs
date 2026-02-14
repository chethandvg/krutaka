using Krutaka.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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

        // Validate glob patterns at startup (fail-fast)
        if (options.AutoGrantPatterns.Length > 0)
        {
            // Create a validator (no logger needed for startup validation)
            var validator = new GlobPatternValidator();
            var validationResult = validator.ValidatePatterns(options.AutoGrantPatterns, options.CeilingDirectory);

            if (!validationResult.IsValid)
            {
                var errorMessages = string.Join(Environment.NewLine, validationResult.Errors);
                throw new InvalidOperationException(
                    $"Invalid glob patterns in AutoGrantPatterns configuration:{Environment.NewLine}{errorMessages}");
            }

            // Log warnings if any (will be logged when ILogger is available)
            if (validationResult.Warnings.Count > 0)
            {
                // Warnings will be logged by the validator when used at runtime with a logger
                // For startup, we just validate and let them through
            }
        }

        // Validate command tier overrides at startup (fail-fast)
        if (options.CommandPolicy.TierOverrides.Length > 0)
        {
            // Create a validator (no logger needed for startup validation)
            var tierValidator = new CommandTierConfigValidator();
            var tierValidationResult = tierValidator.ValidateRules(options.CommandPolicy.TierOverrides);

            if (!tierValidationResult.IsValid)
            {
                var errorMessages = string.Join(Environment.NewLine, tierValidationResult.Errors);
                throw new InvalidOperationException(
                    $"Invalid command tier overrides in CommandPolicy configuration:{Environment.NewLine}{errorMessages}");
            }

            // Warnings will be logged when validator is used at runtime with a logger
            // For startup, we just validate and let them through
        }

        // Register options as singleton
        services.AddSingleton(options);

        // Register command approval cache (singleton - v0.3.0)
        // This is shared between AgentOrchestrator and RunCommandTool to track approved commands during retry
        services.AddSingleton<ICommandApprovalCache, CommandApprovalCache>();

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
            
            // Extract additional allowed executables from TierOverrides
            var additionalExecutables = options.CommandPolicy.TierOverrides
                .Select(rule => rule.Executable)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            
            return new CommandPolicy(fileOperations, auditLogger, additionalExecutables);
        });

        // Register session access store (singleton - application-wide lifetime)
        // Note: Although conceptually "per-session", the application doesn't create service scopes,
        // so this is functionally singleton. The store persists for the application lifetime.
        services.AddSingleton<ISessionAccessStore>(sp =>
        {
            return new InMemorySessionAccessStore(options.MaxConcurrentGrants);
        });

        // Register access policy engine (singleton - v0.2.0 dynamic directory scoping)
        services.AddSingleton<IAccessPolicyEngine>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var sessionStore = sp.GetService<ISessionAccessStore>();
            return new LayeredAccessPolicyEngine(
                fileOperations,
                options.CeilingDirectory,
                options.AutoGrantPatterns,
                sessionStore);
        });

        // Register command risk classifier (singleton - v0.3.0 graduated command execution)
        services.AddSingleton<ICommandRiskClassifier>(sp =>
        {
            return new CommandRiskClassifier(options.CommandPolicy.TierOverrides);
        });

        // Register graduated command policy (singleton - v0.3.0 graduated command execution)
        services.AddSingleton<ICommandPolicy>(sp =>
        {
            var classifier = sp.GetRequiredService<ICommandRiskClassifier>();
            var securityPolicy = sp.GetRequiredService<ISecurityPolicy>();
            var policyEngine = sp.GetService<IAccessPolicyEngine>();
            var auditLogger = sp.GetService<IAuditLogger>();
            return new GraduatedCommandPolicy(classifier, securityPolicy, policyEngine, auditLogger, options.CommandPolicy);
        });

        // Register tool registry (singleton - holds registered tools)
        var registry = new ToolRegistry();

        // Get default working directory from options (v0.2.0 - used as fallback when policy engine is null)
        var defaultWorkingDir = options.DefaultWorkingDirectory;

        // Register and add all tool implementations using factories to resolve dependencies
        // v0.2.0: Tools now receive IAccessPolicyEngine for dynamic directory scoping
        // Read-only tools (auto-approve)
        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var policyEngine = sp.GetService<IAccessPolicyEngine>();
            return new ReadFileTool(defaultWorkingDir, fileOperations, policyEngine);
        });

        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var policyEngine = sp.GetService<IAccessPolicyEngine>();
            return new ListFilesTool(defaultWorkingDir, fileOperations, policyEngine);
        });

        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var policyEngine = sp.GetService<IAccessPolicyEngine>();
            return new SearchFilesTool(defaultWorkingDir, fileOperations, policyEngine);
        });

        // Write tools (require approval)
        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var policyEngine = sp.GetService<IAccessPolicyEngine>();
            return new WriteFileTool(defaultWorkingDir, fileOperations, policyEngine);
        });

        services.AddSingleton<ITool>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            var policyEngine = sp.GetService<IAccessPolicyEngine>();
            return new EditFileTool(defaultWorkingDir, fileOperations, policyEngine);
        });

        // Command execution tool (v0.3.0: approval now determined by ICommandPolicy)
        services.AddSingleton<ITool>(sp =>
        {
            var securityPolicy = sp.GetRequiredService<ISecurityPolicy>();
            var policyEngine = sp.GetService<IAccessPolicyEngine>();
            var commandPolicy = sp.GetRequiredService<ICommandPolicy>();
            var approvalCache = sp.GetRequiredService<ICommandApprovalCache>();
            var correlationContextAccessor = sp.GetService<ICorrelationContextAccessor>();
            return new RunCommandTool(defaultWorkingDir, securityPolicy, options.CommandTimeoutSeconds, policyEngine, commandPolicy, approvalCache, correlationContextAccessor);
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
