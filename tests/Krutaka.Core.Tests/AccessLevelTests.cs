using FluentAssertions;

namespace Krutaka.Core.Tests;

public class AccessLevelTests
{
    [Fact]
    public void AccessLevel_Should_HaveCorrectValues()
    {
        // Assert
        ((int)AccessLevel.ReadOnly).Should().Be(0);
        ((int)AccessLevel.ReadWrite).Should().Be(1);
        ((int)AccessLevel.Execute).Should().Be(2);
    }

    [Theory]
    [InlineData(AccessLevel.ReadOnly)]
    [InlineData(AccessLevel.ReadWrite)]
    [InlineData(AccessLevel.Execute)]
    public void AccessLevel_Should_ParseFromString(AccessLevel level)
    {
        // Arrange
        var levelString = level.ToString();

        // Act
        var parsed = Enum.Parse<AccessLevel>(levelString);

        // Assert
        parsed.Should().Be(level);
    }

    [Fact]
    public void AccessLevel_Should_HaveThreeValues()
    {
        // Arrange & Act
        var values = Enum.GetValues<AccessLevel>();

        // Assert
        values.Should().HaveCount(3);
        values.Should().Contain(AccessLevel.ReadOnly);
        values.Should().Contain(AccessLevel.ReadWrite);
        values.Should().Contain(AccessLevel.Execute);
    }
}
