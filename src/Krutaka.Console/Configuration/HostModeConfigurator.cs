using Krutaka.Core;
using Krutaka.Telegram;
using Krutaka.Tools;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;

namespace Krutaka.Console;

/// <summary>
/// Handles host mode resolution and conditional service registration.
/// </summary>
internal static class HostModeConfigurator
{
    /// <summary>
    /// Resolves the host mode from configuration and CLI arguments.
    /// CLI --mode argument takes precedence over appsettings.json.
    /// </summary>
    /// <param name="configuration">The application configuration.</param>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>The resolved host mode.</returns>
    /// <exception cref="ArgumentException">Thrown when an invalid mode value is specified.</exception>
    public static HostMode ResolveMode(IConfiguration configuration, string[] args)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(args);

        // Check CLI arguments first (--mode takes precedence)
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--mode", StringComparison.OrdinalIgnoreCase))
            {
                // Ensure there's a value after --mode
                if (i + 1 >= args.Length)
                {
                    throw new ArgumentException(
                        "The --mode argument requires a value. Valid values: Console, Telegram, Both",
                        nameof(args));
                }

                var modeValue = args[i + 1];
                if (Enum.TryParse<HostMode>(modeValue, ignoreCase: true, out var cliMode))
                {
                    return cliMode;
                }

                throw new ArgumentException(
                    $"Invalid host mode '{modeValue}' specified via --mode. Valid values: Console, Telegram, Both",
                    nameof(args));
            }
        }

        // Fall back to configuration
        var configMode = configuration["Mode"];
        if (!string.IsNullOrWhiteSpace(configMode))
        {
            if (Enum.TryParse<HostMode>(configMode, ignoreCase: true, out var parsedMode))
            {
                return parsedMode;
            }

            throw new ArgumentException(
                $"Invalid host mode '{configMode}' in configuration. Valid values: Console, Telegram, Both");
        }

        // Default to Console for backward compatibility
        return HostMode.Console;
    }

    /// <summary>
    /// Configures SessionManagerOptions based on the host mode.
    /// </summary>
    /// <param name="mode">The host mode.</param>
    /// <param name="configuration">The application configuration.</param>
    /// <returns>The configured SessionManagerOptions.</returns>
    public static SessionManagerOptions ConfigureSessionManager(HostMode mode, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        return mode switch
        {
            HostMode.Console => new SessionManagerOptions
            {
                MaxActiveSessions = 1, // Console is single-session
                EvictionStrategy = EvictionStrategy.TerminateOldest,
                IdleTimeout = TimeSpan.Zero, // No idle timeout for Console
                GlobalMaxTokensPerHour = 1_000_000, // 1M tokens/hour
                MaxSessionsPerUser = 1, // Single user in Console mode
                DeadmanSwitch = ReadDeadmanSwitchOptions(configuration)
            },
            HostMode.Telegram or HostMode.Both => new SessionManagerOptions
            {
                MaxActiveSessions = configuration.GetValue<int>("SessionManager:MaxActiveSessions", 10),
                EvictionStrategy = Enum.Parse<EvictionStrategy>(
                    configuration["SessionManager:EvictionStrategy"] ?? "SuspendOldestIdle",
                    ignoreCase: true),
                IdleTimeout = TimeSpan.FromMinutes(
                    configuration.GetValue<int>("SessionManager:IdleTimeoutMinutes", 15)),
                GlobalMaxTokensPerHour = configuration.GetValue<int>(
                    "SessionManager:GlobalMaxTokensPerHour", 1_000_000),
                MaxSessionsPerUser = configuration.GetValue<int>("SessionManager:MaxSessionsPerUser", 3),
                DeadmanSwitch = ReadDeadmanSwitchOptions(configuration)
            },
            _ => throw new InvalidOperationException($"Unexpected host mode: {mode}")
        };
    }

    /// <summary>
    /// Reads DeadmanSwitch configuration from the Agent:DeadmanSwitch section.
    /// Returns default options (30 min) if the section is absent or values are not specified.
    /// </summary>
    private static DeadmanSwitchOptions ReadDeadmanSwitchOptions(IConfiguration configuration)
    {
        var maxUnattendedMinutes = configuration.GetValue<int>("Agent:DeadmanSwitch:MaxUnattendedMinutes", 30);
        var heartbeatIntervalMinutes = configuration.GetValue<int>("Agent:DeadmanSwitch:HeartbeatIntervalMinutes", 5);
        return new DeadmanSwitchOptions(maxUnattendedMinutes, heartbeatIntervalMinutes);
    }

    /// <summary>
    /// Registers mode-specific services (ConsoleUI, TelegramBotService, ApprovalHandler).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="mode">The host mode.</param>
    /// <param name="configuration">The application configuration.</param>
    /// <param name="workingDirectory">The working directory for ApprovalHandler.</param>
    public static void RegisterModeSpecificServices(
        IServiceCollection services,
        HostMode mode,
        IConfiguration configuration,
        string workingDirectory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(workingDirectory);

        switch (mode)
        {
            case HostMode.Console:
                // Console mode: Register ConsoleUI and ApprovalHandler only
                services.AddSingleton(sp =>
                {
                    var fileOps = sp.GetRequiredService<IFileOperations>();
                    return new ApprovalHandler(workingDirectory, fileOps);
                });
                services.AddSingleton<ConsoleUI>();
                Log.Information("Console mode: Registered ConsoleUI");
                break;

            case HostMode.Telegram:
                // Telegram mode: Register TelegramBotService as hosted service, skip ConsoleUI
                ValidateTelegramConfiguration(configuration);
                services.AddTelegramBot(configuration);
                services.AddHostedService<TelegramBotService>();
                Log.Information("Telegram mode: Registered TelegramBotService");
                break;

            case HostMode.Both:
                // Both mode: Register both ConsoleUI and TelegramBotService
                ValidateTelegramConfiguration(configuration);
                services.AddSingleton(sp =>
                {
                    var fileOps = sp.GetRequiredService<IFileOperations>();
                    return new ApprovalHandler(workingDirectory, fileOps);
                });
                services.AddSingleton<ConsoleUI>();
                services.AddTelegramBot(configuration);
                services.AddHostedService<TelegramBotService>();
                Log.Information("Both mode: Registered ConsoleUI and TelegramBotService");
                break;

            default:
                throw new InvalidOperationException($"Unexpected host mode: {mode}");
        }
    }

    /// <summary>
    /// Validates that Telegram configuration section exists and is valid.
    /// </summary>
    /// <param name="configuration">The application configuration.</param>
    /// <exception cref="InvalidOperationException">Thrown when Telegram configuration is missing or invalid.</exception>
    private static void ValidateTelegramConfiguration(IConfiguration configuration)
    {
        var telegramSection = configuration.GetSection("Telegram");
        if (!telegramSection.Exists())
        {
            throw new InvalidOperationException(
                "Telegram mode requires a 'Telegram' configuration section in appsettings.json. " +
                "Please add the Telegram configuration section with required properties.");
        }

        var config = telegramSection.Get<TelegramSecurityConfig>();
        if (config is null)
        {
            throw new InvalidOperationException(
                "Telegram configuration section is invalid. " +
                "Please ensure all required properties are present.");
        }

        // Validate required properties - TelegramConfigValidator.Validate will perform full validation during AddTelegramBot,
        // but we do a basic check here to fail fast on obviously invalid configurations
        if (config.AllowedUsers is null || config.AllowedUsers.Length == 0)
        {
            throw new InvalidOperationException(
                "Telegram configuration is invalid: AllowedUsers must be specified and contain at least one user.");
        }
    }
}
