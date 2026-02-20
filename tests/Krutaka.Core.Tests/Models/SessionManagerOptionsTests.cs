using FluentAssertions;

namespace Krutaka.Core.Tests;

public class SessionManagerOptionsTests
{
    [Fact]
    public void Constructor_Should_UseDefaultValues()
    {
        // Act
        var options = new SessionManagerOptions();

        // Assert
        options.MaxActiveSessions.Should().Be(10);
        options.IdleTimeoutValue.Should().Be(TimeSpan.FromMinutes(15));
        options.SuspendedTtlValue.Should().Be(TimeSpan.FromHours(24));
        options.GlobalMaxTokensPerHour.Should().Be(1_000_000);
        options.MaxSessionsPerUser.Should().Be(3);
        options.EvictionStrategy.Should().Be(EvictionStrategy.SuspendOldestIdle);
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenMaxActiveSessionsIsNegative()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SessionManagerOptions(MaxActiveSessions: -1));
        exception.ParamName.Should().Be("maxActiveSessions");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenMaxSessionsPerUserIsNegative()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SessionManagerOptions(MaxSessionsPerUser: -1));
        exception.ParamName.Should().Be("maxSessionsPerUser");
    }

    [Fact]
    public void Constructor_Should_AcceptCustomValues()
    {
        // Arrange
        var customIdleTimeout = TimeSpan.FromMinutes(30);
        var customSuspendedTtl = TimeSpan.FromHours(48);

        // Act
        var options = new SessionManagerOptions(
            MaxActiveSessions: 20,
            IdleTimeout: customIdleTimeout,
            SuspendedTtl: customSuspendedTtl,
            GlobalMaxTokensPerHour: 2_000_000,
            MaxSessionsPerUser: 5,
            EvictionStrategy: EvictionStrategy.RejectNew);

        // Assert
        options.MaxActiveSessions.Should().Be(20);
        options.IdleTimeoutValue.Should().Be(customIdleTimeout);
        options.SuspendedTtlValue.Should().Be(customSuspendedTtl);
        options.GlobalMaxTokensPerHour.Should().Be(2_000_000);
        options.MaxSessionsPerUser.Should().Be(5);
        options.EvictionStrategy.Should().Be(EvictionStrategy.RejectNew);
    }

    [Fact]
    public void IdleTimeoutValue_Should_UseDefaultWhenNull()
    {
        // Act
        var options = new SessionManagerOptions(IdleTimeout: null);

        // Assert
        options.IdleTimeoutValue.Should().Be(TimeSpan.FromMinutes(15));
    }

    [Fact]
    public void SuspendedTtlValue_Should_UseDefaultWhenNull()
    {
        // Act
        var options = new SessionManagerOptions(SuspendedTtl: null);

        // Assert
        options.SuspendedTtlValue.Should().Be(TimeSpan.FromHours(24));
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenIdleTimeoutIsNegative()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SessionManagerOptions(IdleTimeout: TimeSpan.FromMinutes(-1)));
        exception.ParamName.Should().Be(nameof(SessionManagerOptions.IdleTimeout));
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenSuspendedTtlIsNegative()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SessionManagerOptions(SuspendedTtl: TimeSpan.FromHours(-1)));
        exception.ParamName.Should().Be(nameof(SessionManagerOptions.SuspendedTtl));
    }

    [Fact]
    public void Constructor_Should_AcceptZeroIdleTimeout()
    {
        // Act
        var options = new SessionManagerOptions(IdleTimeout: TimeSpan.Zero);

        // Assert
        options.IdleTimeoutValue.Should().Be(TimeSpan.Zero);
    }

    [Fact]
    public void Constructor_Should_AcceptZeroSuspendedTtl()
    {
        // Act
        var options = new SessionManagerOptions(SuspendedTtl: TimeSpan.Zero);

        // Assert
        options.SuspendedTtlValue.Should().Be(TimeSpan.Zero);
    }
}
