using FluentAssertions;

namespace Krutaka.Core.Tests;

public class AnomalySeverityTests
{
    [Fact]
    public void AnomalySeverity_Should_HaveCorrectValues()
    {
        // Assert
        ((int)AnomalySeverity.None).Should().Be(0);
        ((int)AnomalySeverity.Low).Should().Be(1);
        ((int)AnomalySeverity.Medium).Should().Be(2);
        ((int)AnomalySeverity.High).Should().Be(3);
    }

    [Fact]
    public void AnomalySeverity_Should_HaveFourValues()
    {
        // Act
        var values = Enum.GetValues<AnomalySeverity>();

        // Assert
        values.Should().HaveCount(4);
        values.Should().Contain(AnomalySeverity.None);
        values.Should().Contain(AnomalySeverity.Low);
        values.Should().Contain(AnomalySeverity.Medium);
        values.Should().Contain(AnomalySeverity.High);
    }

    [Fact]
    public void AnomalySeverity_Should_BeOrderedAscendingBySeverity()
    {
        // Assert — higher numeric value means greater severity
        ((int)AnomalySeverity.None).Should().BeLessThan((int)AnomalySeverity.Low);
        ((int)AnomalySeverity.Low).Should().BeLessThan((int)AnomalySeverity.Medium);
        ((int)AnomalySeverity.Medium).Should().BeLessThan((int)AnomalySeverity.High);
    }

    [Theory]
    [InlineData(AnomalySeverity.None)]
    [InlineData(AnomalySeverity.Low)]
    [InlineData(AnomalySeverity.Medium)]
    [InlineData(AnomalySeverity.High)]
    public void AnomalySeverity_Should_ParseFromString(AnomalySeverity severity)
    {
        // Arrange
        var severityString = severity.ToString();

        // Act
        var parsed = Enum.Parse<AnomalySeverity>(severityString);

        // Assert
        parsed.Should().Be(severity);
    }
}
