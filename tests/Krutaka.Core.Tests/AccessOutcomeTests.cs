using FluentAssertions;

namespace Krutaka.Core.Tests;

public class AccessOutcomeTests
{
    [Fact]
    public void AccessOutcome_Should_HaveCorrectValues()
    {
        // Assert
        ((int)AccessOutcome.Granted).Should().Be(0);
        ((int)AccessOutcome.Denied).Should().Be(1);
        ((int)AccessOutcome.RequiresApproval).Should().Be(2);
    }

    [Theory]
    [InlineData(AccessOutcome.Granted)]
    [InlineData(AccessOutcome.Denied)]
    [InlineData(AccessOutcome.RequiresApproval)]
    public void AccessOutcome_Should_ParseFromString(AccessOutcome outcome)
    {
        // Arrange
        var outcomeString = outcome.ToString();

        // Act
        var parsed = Enum.Parse<AccessOutcome>(outcomeString);

        // Assert
        parsed.Should().Be(outcome);
    }

    [Fact]
    public void AccessOutcome_Should_HaveThreeValues()
    {
        // Arrange & Act
        var values = Enum.GetValues<AccessOutcome>();

        // Assert
        values.Should().HaveCount(3);
        values.Should().Contain(AccessOutcome.Granted);
        values.Should().Contain(AccessOutcome.Denied);
        values.Should().Contain(AccessOutcome.RequiresApproval);
    }
}
