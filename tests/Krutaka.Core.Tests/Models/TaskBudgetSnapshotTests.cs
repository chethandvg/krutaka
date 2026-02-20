using FluentAssertions;

namespace Krutaka.Core.Tests;

public class TaskBudgetSnapshotTests
{
    [Fact]
    public void TaskBudgetSnapshot_Should_StoreAllProperties()
    {
        // Act
        var snapshot = new TaskBudgetSnapshot(
            TokensConsumed: 50_000,
            ToolCallsConsumed: 25,
            FilesModified: 5,
            ProcessesSpawned: 2,
            TokensPercentage: 0.25,
            ToolCallsPercentage: 0.25,
            FilesModifiedPercentage: 0.25,
            ProcessesSpawnedPercentage: 0.20
        );

        // Assert
        snapshot.TokensConsumed.Should().Be(50_000);
        snapshot.ToolCallsConsumed.Should().Be(25);
        snapshot.FilesModified.Should().Be(5);
        snapshot.ProcessesSpawned.Should().Be(2);
        snapshot.TokensPercentage.Should().BeApproximately(0.25, 1e-9);
        snapshot.ToolCallsPercentage.Should().BeApproximately(0.25, 1e-9);
        snapshot.FilesModifiedPercentage.Should().BeApproximately(0.25, 1e-9);
        snapshot.ProcessesSpawnedPercentage.Should().BeApproximately(0.20, 1e-9);
    }

    [Fact]
    public void TaskBudgetSnapshot_Should_SupportValueEquality()
    {
        // Arrange
        var snapshot1 = new TaskBudgetSnapshot(10_000, 5, 1, 0, 0.05, 0.05, 0.05, 0.0);
        var snapshot2 = new TaskBudgetSnapshot(10_000, 5, 1, 0, 0.05, 0.05, 0.05, 0.0);

        // Assert
        snapshot1.Should().Be(snapshot2);
        (snapshot1 == snapshot2).Should().BeTrue();
    }

    [Fact]
    public void TaskBudgetSnapshot_Should_NotBeEqual_WhenValuesDiffer()
    {
        // Arrange
        var snapshot1 = new TaskBudgetSnapshot(10_000, 5, 1, 0, 0.05, 0.05, 0.05, 0.0);
        var snapshot2 = new TaskBudgetSnapshot(20_000, 5, 1, 0, 0.10, 0.05, 0.05, 0.0);

        // Assert
        snapshot1.Should().NotBe(snapshot2);
    }

    [Fact]
    public void TaskBudgetSnapshot_Should_RepresentZeroConsumption()
    {
        // Act
        var snapshot = new TaskBudgetSnapshot(0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0);

        // Assert
        snapshot.TokensConsumed.Should().Be(0);
        snapshot.ToolCallsConsumed.Should().Be(0);
        snapshot.FilesModified.Should().Be(0);
        snapshot.ProcessesSpawned.Should().Be(0);
        snapshot.TokensPercentage.Should().Be(0.0);
        snapshot.ToolCallsPercentage.Should().Be(0.0);
        snapshot.FilesModifiedPercentage.Should().Be(0.0);
        snapshot.ProcessesSpawnedPercentage.Should().Be(0.0);
    }

    [Fact]
    public void TaskBudgetSnapshot_Should_RepresentFullConsumption()
    {
        // Act
        var snapshot = new TaskBudgetSnapshot(200_000, 100, 20, 10, 1.0, 1.0, 1.0, 1.0);

        // Assert
        snapshot.TokensPercentage.Should().Be(1.0);
        snapshot.ToolCallsPercentage.Should().Be(1.0);
        snapshot.FilesModifiedPercentage.Should().Be(1.0);
        snapshot.ProcessesSpawnedPercentage.Should().Be(1.0);
    }
}
