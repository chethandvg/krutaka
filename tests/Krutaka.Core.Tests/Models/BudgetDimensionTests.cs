using FluentAssertions;

namespace Krutaka.Core.Tests;

public class BudgetDimensionTests
{
    [Fact]
    public void BudgetDimension_Should_HaveCorrectValues()
    {
        // Assert
        ((int)BudgetDimension.Tokens).Should().Be(0);
        ((int)BudgetDimension.ToolCalls).Should().Be(1);
        ((int)BudgetDimension.FilesModified).Should().Be(2);
        ((int)BudgetDimension.ProcessesSpawned).Should().Be(3);
    }

    [Fact]
    public void BudgetDimension_Should_HaveFourValues()
    {
        // Act
        var values = Enum.GetValues<BudgetDimension>();

        // Assert
        values.Should().HaveCount(4);
        values.Should().Contain(BudgetDimension.Tokens);
        values.Should().Contain(BudgetDimension.ToolCalls);
        values.Should().Contain(BudgetDimension.FilesModified);
        values.Should().Contain(BudgetDimension.ProcessesSpawned);
    }

    [Theory]
    [InlineData(BudgetDimension.Tokens)]
    [InlineData(BudgetDimension.ToolCalls)]
    [InlineData(BudgetDimension.FilesModified)]
    [InlineData(BudgetDimension.ProcessesSpawned)]
    public void BudgetDimension_Should_ParseFromString(BudgetDimension dimension)
    {
        // Arrange
        var dimensionString = dimension.ToString();

        // Act
        var parsed = Enum.Parse<BudgetDimension>(dimensionString);

        // Assert
        parsed.Should().Be(dimension);
    }
}
