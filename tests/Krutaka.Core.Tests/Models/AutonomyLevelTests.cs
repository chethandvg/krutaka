using FluentAssertions;

namespace Krutaka.Core.Tests;

public class AutonomyLevelTests
{
    [Fact]
    public void AutonomyLevel_Should_HaveCorrectValues()
    {
        // Assert
        ((int)AutonomyLevel.Supervised).Should().Be(0);
        ((int)AutonomyLevel.Guided).Should().Be(1);
        ((int)AutonomyLevel.SemiAutonomous).Should().Be(2);
        ((int)AutonomyLevel.Autonomous).Should().Be(3);
    }

    [Fact]
    public void AutonomyLevel_Should_HaveFourValues()
    {
        // Act
        var values = Enum.GetValues<AutonomyLevel>();

        // Assert
        values.Should().HaveCount(4);
        values.Should().Contain(AutonomyLevel.Supervised);
        values.Should().Contain(AutonomyLevel.Guided);
        values.Should().Contain(AutonomyLevel.SemiAutonomous);
        values.Should().Contain(AutonomyLevel.Autonomous);
    }

    [Fact]
    public void AutonomyLevel_Should_BeOrderedAscendingByAutonomy()
    {
        // Assert — higher numeric value means more autonomy
        ((int)AutonomyLevel.Supervised).Should().BeLessThan((int)AutonomyLevel.Guided);
        ((int)AutonomyLevel.Guided).Should().BeLessThan((int)AutonomyLevel.SemiAutonomous);
        ((int)AutonomyLevel.SemiAutonomous).Should().BeLessThan((int)AutonomyLevel.Autonomous);
    }

    [Theory]
    [InlineData(AutonomyLevel.Supervised)]
    [InlineData(AutonomyLevel.Guided)]
    [InlineData(AutonomyLevel.SemiAutonomous)]
    [InlineData(AutonomyLevel.Autonomous)]
    public void AutonomyLevel_Should_ParseFromString(AutonomyLevel level)
    {
        // Arrange
        var levelString = level.ToString();

        // Act
        var parsed = Enum.Parse<AutonomyLevel>(levelString);

        // Assert
        parsed.Should().Be(level);
    }
}
