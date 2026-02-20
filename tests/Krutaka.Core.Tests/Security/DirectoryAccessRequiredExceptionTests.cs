using FluentAssertions;

namespace Krutaka.Core.Tests;

public class DirectoryAccessRequiredExceptionTests
{
    [Fact]
    public void Constructor_WithValidArguments_SetsProperties()
    {
        // Arrange & Act
        var exception = new DirectoryAccessRequiredException(@"C:\projects\test", AccessLevel.ReadWrite, "Need to write config files");

        // Assert
        exception.Path.Should().Be(@"C:\projects\test");
        exception.RequestedLevel.Should().Be(AccessLevel.ReadWrite);
        exception.Justification.Should().Be("Need to write config files");
        exception.Message.Should().Contain(@"C:\projects\test");
        exception.Message.Should().Contain("ReadWrite");
    }

    [Fact]
    public void Constructor_WithNullPath_ThrowsArgumentException()
    {
        // Act
        var act = () => new DirectoryAccessRequiredException(null!, AccessLevel.ReadOnly, "Test");

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_WithEmptyPath_ThrowsArgumentException()
    {
        // Act
        var act = () => new DirectoryAccessRequiredException("", AccessLevel.ReadOnly, "Test");

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_WithNullJustification_ThrowsArgumentException()
    {
        // Act
        var act = () => new DirectoryAccessRequiredException(@"C:\test", AccessLevel.ReadOnly, null!);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_WithEmptyJustification_ThrowsArgumentException()
    {
        // Act
        var act = () => new DirectoryAccessRequiredException(@"C:\test", AccessLevel.ReadOnly, "");

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_WithInnerException_SetsInnerException()
    {
        // Arrange
        var innerException = new InvalidOperationException("Inner");

        // Act
        var exception = new DirectoryAccessRequiredException(@"C:\test", AccessLevel.ReadOnly, "Test", innerException);

        // Assert
        exception.InnerException.Should().Be(innerException);
        exception.Path.Should().Be(@"C:\test");
    }
}
