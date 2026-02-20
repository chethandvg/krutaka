using FluentAssertions;

namespace Krutaka.Core.Tests;

public class AgentBehaviorSnapshotTests
{
    [Fact]
    public void AgentBehaviorSnapshot_Should_StoreAllProperties()
    {
        // Act
        var snapshot = new AgentBehaviorSnapshot(
            ToolCallFrequencyPerMinute: 2.5,
            RepeatedFailureCount: 3,
            AccessEscalationCount: 1,
            FileModificationVelocity: 0.8,
            DirectoryScopeExpansionCount: 4
        );

        // Assert
        snapshot.ToolCallFrequencyPerMinute.Should().BeApproximately(2.5, 1e-9);
        snapshot.RepeatedFailureCount.Should().Be(3);
        snapshot.AccessEscalationCount.Should().Be(1);
        snapshot.FileModificationVelocity.Should().BeApproximately(0.8, 1e-9);
        snapshot.DirectoryScopeExpansionCount.Should().Be(4);
    }

    [Fact]
    public void AgentBehaviorSnapshot_Should_RepresentIdleState()
    {
        // Act
        var snapshot = new AgentBehaviorSnapshot(
            ToolCallFrequencyPerMinute: 0.0,
            RepeatedFailureCount: 0,
            AccessEscalationCount: 0,
            FileModificationVelocity: 0.0,
            DirectoryScopeExpansionCount: 0
        );

        // Assert
        snapshot.ToolCallFrequencyPerMinute.Should().Be(0.0);
        snapshot.RepeatedFailureCount.Should().Be(0);
        snapshot.AccessEscalationCount.Should().Be(0);
        snapshot.FileModificationVelocity.Should().Be(0.0);
        snapshot.DirectoryScopeExpansionCount.Should().Be(0);
    }

    [Fact]
    public void AgentBehaviorSnapshot_Should_SupportValueEquality()
    {
        // Arrange
        var snapshot1 = new AgentBehaviorSnapshot(1.0, 2, 0, 0.5, 1);
        var snapshot2 = new AgentBehaviorSnapshot(1.0, 2, 0, 0.5, 1);

        // Assert
        snapshot1.Should().Be(snapshot2);
        (snapshot1 == snapshot2).Should().BeTrue();
    }

    [Fact]
    public void AgentBehaviorSnapshot_Should_NotBeEqual_WhenValuesDiffer()
    {
        // Arrange
        var snapshot1 = new AgentBehaviorSnapshot(1.0, 2, 0, 0.5, 1);
        var snapshot2 = new AgentBehaviorSnapshot(1.0, 5, 0, 0.5, 1);

        // Assert
        snapshot1.Should().NotBe(snapshot2);
    }

    [Fact]
    public void AgentBehaviorSnapshot_ToolCallFrequencyPerMinute_ShouldUsePerMinuteUnit()
    {
        // Values above 10 are considered unusual per the v0.5.0 anomaly policy.
        // This test pins the unit as calls-per-minute so that detector implementations
        // don't silently misclassify by a 60x factor.
        var belowThreshold = new AgentBehaviorSnapshot(ToolCallFrequencyPerMinute: 10.0, 0, 0, 0.0, 0);
        var aboveThreshold = new AgentBehaviorSnapshot(ToolCallFrequencyPerMinute: 10.1, 0, 0, 0.0, 0);

        belowThreshold.ToolCallFrequencyPerMinute.Should().BeLessOrEqualTo(10.0);
        aboveThreshold.ToolCallFrequencyPerMinute.Should().BeGreaterThan(10.0);
    }
}
