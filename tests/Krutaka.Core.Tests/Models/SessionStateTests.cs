using FluentAssertions;

namespace Krutaka.Core.Tests;

public class SessionStateTests
{
    [Fact]
    public void Enum_Should_HaveActiveValue()
    {
        // Act & Assert
        Enum.IsDefined(SessionState.Active).Should().BeTrue();
    }

    [Fact]
    public void Enum_Should_HaveIdleValue()
    {
        // Act & Assert
        Enum.IsDefined(SessionState.Idle).Should().BeTrue();
    }

    [Fact]
    public void Enum_Should_HaveSuspendedValue()
    {
        // Act & Assert
        Enum.IsDefined(SessionState.Suspended).Should().BeTrue();
    }

    [Fact]
    public void Enum_Should_HaveTerminatedValue()
    {
        // Act & Assert
        Enum.IsDefined(SessionState.Terminated).Should().BeTrue();
    }

    [Fact]
    public void Enum_Should_HaveExactlyFourValues()
    {
        // Act
        var values = Enum.GetValues<SessionState>();

        // Assert
        values.Length.Should().Be(4);
    }
}
