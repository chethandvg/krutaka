using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Krutaka.Console.Tests.Configuration;

/// <summary>
/// Unit tests for HostModeConfigurator.ConfigureSessionManager.
/// </summary>
public class HostModeConfiguratorTests
{
    private static IConfiguration EmptyConfig() => new ConfigurationBuilder().Build();

    private static IConfiguration Config(Dictionary<string, string?> values) => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    // --- Console mode ---

    [Fact]
    public void ConfigureSessionManager_ConsoleMode_Should_SetMaxActiveSessionsToOne()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Console, EmptyConfig());
        opts.MaxActiveSessions.Should().Be(1);
    }

    [Fact]
    public void ConfigureSessionManager_ConsoleMode_Should_SetIdleTimeoutToZero()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Console, EmptyConfig());
        opts.IdleTimeout.Should().Be(TimeSpan.Zero);
    }

    [Fact]
    public void ConfigureSessionManager_ConsoleMode_Should_SetEvictionStrategyToTerminateOldest()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Console, EmptyConfig());
        opts.EvictionStrategy.Should().Be(EvictionStrategy.TerminateOldest);
    }

    [Fact]
    public void ConfigureSessionManager_ConsoleMode_Should_SetMaxSessionsPerUserToOne()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Console, EmptyConfig());
        opts.MaxSessionsPerUser.Should().Be(1);
    }

    [Fact]
    public void ConfigureSessionManager_ConsoleMode_Should_SetDefaultGlobalTokenLimit()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Console, EmptyConfig());
        opts.GlobalMaxTokensPerHour.Should().Be(1_000_000);
    }

    // --- Telegram mode defaults ---

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseDefaultMaxActiveSessions_WhenNotConfigured()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, EmptyConfig());
        opts.MaxActiveSessions.Should().Be(10);
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseDefaultIdleTimeoutOfFifteenMinutes()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, EmptyConfig());
        opts.IdleTimeout.Should().Be(TimeSpan.FromMinutes(15));
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseDefaultMaxSessionsPerUser()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, EmptyConfig());
        opts.MaxSessionsPerUser.Should().Be(3);
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseDefaultGlobalTokenLimit()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, EmptyConfig());
        opts.GlobalMaxTokensPerHour.Should().Be(1_000_000);
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseDefaultEvictionStrategy_SuspendOldestIdle()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, EmptyConfig());
        opts.EvictionStrategy.Should().Be(EvictionStrategy.SuspendOldestIdle);
    }

    // --- Telegram mode with custom config ---

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseConfiguredMaxActiveSessions()
    {
        var config = Config(new Dictionary<string, string?> { ["SessionManager:MaxActiveSessions"] = "25" });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, config);
        opts.MaxActiveSessions.Should().Be(25);
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseConfiguredIdleTimeoutMinutes()
    {
        var config = Config(new Dictionary<string, string?> { ["SessionManager:IdleTimeoutMinutes"] = "30" });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, config);
        opts.IdleTimeout.Should().Be(TimeSpan.FromMinutes(30));
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseConfiguredMaxSessionsPerUser()
    {
        var config = Config(new Dictionary<string, string?> { ["SessionManager:MaxSessionsPerUser"] = "5" });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, config);
        opts.MaxSessionsPerUser.Should().Be(5);
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseConfiguredGlobalMaxTokensPerHour()
    {
        var config = Config(new Dictionary<string, string?> { ["SessionManager:GlobalMaxTokensPerHour"] = "500000" });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, config);
        opts.GlobalMaxTokensPerHour.Should().Be(500_000);
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseConfiguredEvictionStrategy()
    {
        var config = Config(new Dictionary<string, string?> { ["SessionManager:EvictionStrategy"] = "TerminateOldest" });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, config);
        opts.EvictionStrategy.Should().Be(EvictionStrategy.TerminateOldest);
    }

    // --- Both mode ---

    [Fact]
    public void ConfigureSessionManager_BothMode_Should_UseDefaultMaxActiveSessions_WhenNotConfigured()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Both, EmptyConfig());
        opts.MaxActiveSessions.Should().Be(10);
    }

    [Fact]
    public void ConfigureSessionManager_BothMode_Should_UseConfiguredMaxActiveSessions()
    {
        var config = Config(new Dictionary<string, string?> { ["SessionManager:MaxActiveSessions"] = "5" });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Both, config);
        opts.MaxActiveSessions.Should().Be(5);
    }

    [Fact]
    public void ConfigureSessionManager_BothMode_Should_UseDefaultIdleTimeout()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Both, EmptyConfig());
        opts.IdleTimeout.Should().Be(TimeSpan.FromMinutes(15));
    }

    // --- Null guard ---

    [Fact]
    public void ConfigureSessionManager_Should_ThrowArgumentNullException_WhenConfigurationIsNull()
    {
        var act = () => HostModeConfigurator.ConfigureSessionManager(HostMode.Console, null!);
        act.Should().Throw<ArgumentNullException>();
    }

    // --- DeadmanSwitch config binding ---

    [Fact]
    public void ConfigureSessionManager_ConsoleMode_Should_UseDefaultDeadmanSwitchOptions_WhenNotConfigured()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Console, EmptyConfig());
        opts.DeadmanSwitchValue.MaxUnattendedMinutes.Should().Be(30);
        opts.DeadmanSwitchValue.HeartbeatIntervalMinutes.Should().Be(5);
    }

    [Fact]
    public void ConfigureSessionManager_ConsoleMode_Should_UseConfiguredDeadmanSwitchMaxUnattendedMinutes()
    {
        var config = Config(new Dictionary<string, string?> { ["Agent:DeadmanSwitch:MaxUnattendedMinutes"] = "45" });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Console, config);
        opts.DeadmanSwitchValue.MaxUnattendedMinutes.Should().Be(45);
    }

    [Fact]
    public void ConfigureSessionManager_ConsoleMode_Should_UseZeroMaxUnattendedMinutes_ToDisable()
    {
        var config = Config(new Dictionary<string, string?> { ["Agent:DeadmanSwitch:MaxUnattendedMinutes"] = "0" });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Console, config);
        opts.DeadmanSwitchValue.MaxUnattendedMinutes.Should().Be(0);
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseDefaultDeadmanSwitchOptions_WhenNotConfigured()
    {
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, EmptyConfig());
        opts.DeadmanSwitchValue.MaxUnattendedMinutes.Should().Be(30);
        opts.DeadmanSwitchValue.HeartbeatIntervalMinutes.Should().Be(5);
    }

    [Fact]
    public void ConfigureSessionManager_TelegramMode_Should_UseConfiguredDeadmanSwitchOptions()
    {
        var config = Config(new Dictionary<string, string?>
        {
            ["Agent:DeadmanSwitch:MaxUnattendedMinutes"] = "20",
            ["Agent:DeadmanSwitch:HeartbeatIntervalMinutes"] = "3"
        });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Telegram, config);
        opts.DeadmanSwitchValue.MaxUnattendedMinutes.Should().Be(20);
        opts.DeadmanSwitchValue.HeartbeatIntervalMinutes.Should().Be(3);
    }

    [Fact]
    public void ConfigureSessionManager_BothMode_Should_UseConfiguredDeadmanSwitchOptions()
    {
        var config = Config(new Dictionary<string, string?> { ["Agent:DeadmanSwitch:MaxUnattendedMinutes"] = "10" });
        var opts = HostModeConfigurator.ConfigureSessionManager(HostMode.Both, config);
        opts.DeadmanSwitchValue.MaxUnattendedMinutes.Should().Be(10);
    }
}
