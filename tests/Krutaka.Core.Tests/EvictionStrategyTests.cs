using FluentAssertions;

namespace Krutaka.Core.Tests;

public class EvictionStrategyTests
{
    [Fact]
    public void Enum_Should_HaveSuspendOldestIdleValue()
    {
        // Act & Assert
        Enum.IsDefined(EvictionStrategy.SuspendOldestIdle).Should().BeTrue();
    }

    [Fact]
    public void Enum_Should_HaveRejectNewValue()
    {
        // Act & Assert
        Enum.IsDefined(EvictionStrategy.RejectNew).Should().BeTrue();
    }

    [Fact]
    public void Enum_Should_HaveTerminateOldestValue()
    {
        // Act & Assert
        Enum.IsDefined(EvictionStrategy.TerminateOldest).Should().BeTrue();
    }

    [Fact]
    public void Enum_Should_HaveExactlyThreeValues()
    {
        // Act
        var values = Enum.GetValues<EvictionStrategy>();

        // Assert
        values.Length.Should().Be(3);
    }
}
