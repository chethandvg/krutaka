using FluentAssertions;

namespace Krutaka.Core.Tests;

public class IBehaviorAnomalyDetectorTests
{
    private sealed class StubAnomalyDetector : IBehaviorAnomalyDetector
    {
        public Task<AnomalyAssessment> AssessAsync(AgentBehaviorSnapshot snapshot, CancellationToken cancellationToken)
        {
            if (snapshot.ToolCallFrequencyPerMinute > 10.0)
            {
                return Task.FromResult(new AnomalyAssessment(
                    IsAnomalous: true,
                    Reason: "Tool call frequency exceeds threshold",
                    Severity: AnomalySeverity.High
                ));
            }

            return Task.FromResult(new AnomalyAssessment(
                IsAnomalous: false,
                Reason: null,
                Severity: AnomalySeverity.None
            ));
        }
    }

    [Fact]
    public void IBehaviorAnomalyDetector_Should_BeAssignableFromStubImplementation()
    {
        // Act
        IBehaviorAnomalyDetector detector = new StubAnomalyDetector();

        // Assert
        detector.Should().NotBeNull();
        detector.Should().BeAssignableTo<IBehaviorAnomalyDetector>();
    }

    [Fact]
    public async Task AssessAsync_Should_ReturnNonAnomalous_ForNormalBehavior()
    {
        // Arrange
        IBehaviorAnomalyDetector detector = new StubAnomalyDetector();
        var snapshot = new AgentBehaviorSnapshot(
            ToolCallFrequencyPerMinute: 1.0,
            RepeatedFailureCount: 0,
            AccessEscalationCount: 0,
            FileModificationVelocity: 0.2,
            DirectoryScopeExpansionCount: 1
        );

        // Act
        AnomalyAssessment assessment = await detector.AssessAsync(snapshot, CancellationToken.None);

        // Assert
        assessment.IsAnomalous.Should().BeFalse();
        assessment.Reason.Should().BeNull();
        assessment.Severity.Should().Be(AnomalySeverity.None);
    }

    [Fact]
    public async Task AssessAsync_Should_ReturnAnomalous_ForHighFrequencyToolCalls()
    {
        // Arrange
        IBehaviorAnomalyDetector detector = new StubAnomalyDetector();
        var snapshot = new AgentBehaviorSnapshot(
            ToolCallFrequencyPerMinute: 50.0,
            RepeatedFailureCount: 0,
            AccessEscalationCount: 0,
            FileModificationVelocity: 0.0,
            DirectoryScopeExpansionCount: 0
        );

        // Act
        AnomalyAssessment assessment = await detector.AssessAsync(snapshot, CancellationToken.None);

        // Assert
        assessment.IsAnomalous.Should().BeTrue();
        assessment.Reason.Should().NotBeNullOrEmpty();
        assessment.Severity.Should().Be(AnomalySeverity.High);
    }
}
