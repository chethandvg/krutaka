using FluentAssertions;

namespace Krutaka.Core.Tests;

public class AgentBehaviorSnapshotTests
{
    [Fact]
    public void AgentBehaviorSnapshot_Should_StoreAllProperties()
    {
        // Act
        var snapshot = new AgentBehaviorSnapshot(
            ToolCallFrequency: 2.5,
            RepeatedFailureCount: 3,
            AccessEscalationCount: 1,
            FileModificationVelocity: 0.8,
            DirectoryScopeExpansionCount: 4
        );

        // Assert
        snapshot.ToolCallFrequency.Should().BeApproximately(2.5, 1e-9);
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
            ToolCallFrequency: 0.0,
            RepeatedFailureCount: 0,
            AccessEscalationCount: 0,
            FileModificationVelocity: 0.0,
            DirectoryScopeExpansionCount: 0
        );

        // Assert
        snapshot.ToolCallFrequency.Should().Be(0.0);
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
}
