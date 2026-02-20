using FluentAssertions;

namespace Krutaka.Core.Tests;

public class AnomalyAssessmentTests
{
    [Fact]
    public void AnomalyAssessment_Should_StoreAllProperties()
    {
        // Act
        var assessment = new AnomalyAssessment(
            IsAnomalous: true,
            Reason: "Excessive tool call frequency",
            Severity: AnomalySeverity.High
        );

        // Assert
        assessment.IsAnomalous.Should().BeTrue();
        assessment.Reason.Should().Be("Excessive tool call frequency");
        assessment.Severity.Should().Be(AnomalySeverity.High);
    }

    [Fact]
    public void AnomalyAssessment_Should_AllowNullReason_WhenNotAnomalous()
    {
        // Act
        var assessment = new AnomalyAssessment(
            IsAnomalous: false,
            Reason: null,
            Severity: AnomalySeverity.None
        );

        // Assert
        assessment.IsAnomalous.Should().BeFalse();
        assessment.Reason.Should().BeNull();
        assessment.Severity.Should().Be(AnomalySeverity.None);
    }

    [Fact]
    public void AnomalyAssessment_Should_SupportValueEquality()
    {
        // Arrange
        var assessment1 = new AnomalyAssessment(true, "Loop detected", AnomalySeverity.Medium);
        var assessment2 = new AnomalyAssessment(true, "Loop detected", AnomalySeverity.Medium);

        // Assert
        assessment1.Should().Be(assessment2);
        (assessment1 == assessment2).Should().BeTrue();
    }

    [Fact]
    public void AnomalyAssessment_Should_NotBeEqual_WhenValuesDiffer()
    {
        // Arrange
        var assessment1 = new AnomalyAssessment(true, "Loop detected", AnomalySeverity.Medium);
        var assessment2 = new AnomalyAssessment(true, "Loop detected", AnomalySeverity.High);

        // Assert
        assessment1.Should().NotBe(assessment2);
    }
}
