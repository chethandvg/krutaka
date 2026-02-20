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
    /// <param name="autonomyLevelOptions">Optional autonomy level options. Defaults to Guided if not provided.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddAgentTools(
        this IServiceCollection services,
        Action<ToolOptions>? configureOptions = null,
        AutonomyLevelOptions? autonomyLevelOptions = null)
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
        services.AddSingleton<IToolOptions>(options);

        // Register autonomy level options (singleton - read-once at session start for per-session immutability)
        var resolvedAutonomyOptions = autonomyLevelOptions ?? new AutonomyLevelOptions();
        resolvedAutonomyOptions.Validate(); // Fail-fast validation at startup
        services.AddSingleton(resolvedAutonomyOptions);

        // Note: ICommandApprovalCache is created per-session by SessionFactory (not registered globally)
        // v0.4.0: Per-session components are created by SessionFactory, not by global DI

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

        // Note: ISessionAccessStore is created per-session by SessionFactory (not registered globally)
        // v0.4.0: Per-session components are created by SessionFactory, not by global DI

        // Register access policy engine (singleton - v0.2.0 dynamic directory scoping)
        // Note: This is the global shared policy engine. SessionFactory creates per-session instances
        // that wrap per-session ISessionAccessStore for session-specific directory grants.
        services.AddSingleton<IAccessPolicyEngine>(sp =>
        {
            var fileOperations = sp.GetRequiredService<IFileOperations>();
            // Global policy engine without session store (Layer 1 & 2 only: hard deny + auto-grant)
            return new LayeredAccessPolicyEngine(
                fileOperations,
                options.CeilingDirectory,
                options.AutoGrantPatterns,
                sessionStore: null); // No session store for global policy engine
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

        // Note: IToolRegistry and ITool instances are created per-session by SessionFactory (not registered globally)
        // v0.4.0: Per-session tool registries with tools scoped to ProjectPath are created by SessionFactory.CreateSessionToolRegistry()
        // SystemPromptBuilder will use the tool registry from the active session, not from global DI.

        // Register session factory (singleton) for v0.4.0 multi-session support
        services.AddSingleton<ISessionFactory>(sp =>
        {
            var claudeClient = sp.GetRequiredService<IClaudeClient>();
            var securityPolicy = sp.GetRequiredService<ISecurityPolicy>();
            var accessPolicyEngine = sp.GetRequiredService<IAccessPolicyEngine>();
            var commandRiskClassifier = sp.GetRequiredService<ICommandRiskClassifier>();
            var auditLogger = sp.GetService<IAuditLogger>();
            var autonomyOptions = sp.GetService<AutonomyLevelOptions>();
            return new SessionFactory(claudeClient, securityPolicy, accessPolicyEngine, commandRiskClassifier, options, auditLogger, autonomyOptions);
        });

        // Register session manager (singleton) for v0.4.0 multi-session lifecycle management
        services.AddSingleton<ISessionManager>(sp =>
        {
            var factory = sp.GetRequiredService<ISessionFactory>();
            var options = sp.GetService<SessionManagerOptions>() ?? new SessionManagerOptions();
            var logger = sp.GetService<ILogger<SessionManager>>();
            return new SessionManager(factory, options, logger);
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
