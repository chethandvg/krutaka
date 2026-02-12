using FluentAssertions;

namespace Krutaka.Core.Tests;

public class DirectoryAccessRequestTests
{
    [Fact]
    public void DirectoryAccessRequest_Should_HaveCorrectProperties()
    {
        // Arrange & Act
        var request = new DirectoryAccessRequest(
            Path: "/home/user/project",
            Level: AccessLevel.ReadWrite,
            Justification: "Need to write configuration files"
        );

        // Assert
        request.Path.Should().Be("/home/user/project");
        request.Level.Should().Be(AccessLevel.ReadWrite);
        request.Justification.Should().Be("Need to write configuration files");
    }

    [Fact]
    public void DirectoryAccessRequest_Should_SupportRecordEquality()
    {
        // Arrange
        var request1 = new DirectoryAccessRequest(
            Path: "/home/user/project",
            Level: AccessLevel.ReadOnly,
            Justification: "Read source files"
        );

        var request2 = new DirectoryAccessRequest(
            Path: "/home/user/project",
            Level: AccessLevel.ReadOnly,
            Justification: "Read source files"
        );

        var request3 = new DirectoryAccessRequest(
            Path: "/home/user/other",
            Level: AccessLevel.ReadOnly,
            Justification: "Read source files"
        );

        // Assert
        request1.Should().Be(request2);
        request1.Should().NotBe(request3);
        request1.GetHashCode().Should().Be(request2.GetHashCode());
    }

    [Fact]
    public void DirectoryAccessRequest_Should_AllowReadOnlyLevel()
    {
        // Arrange & Act
        var request = new DirectoryAccessRequest(
            Path: "/test/path",
            Level: AccessLevel.ReadOnly,
            Justification: "Reading files"
        );

        // Assert
        request.Level.Should().Be(AccessLevel.ReadOnly);
    }

    [Fact]
    public void DirectoryAccessRequest_Should_AllowReadWriteLevel()
    {
        // Arrange & Act
        var request = new DirectoryAccessRequest(
            Path: "/test/path",
            Level: AccessLevel.ReadWrite,
            Justification: "Writing files"
        );

        // Assert
        request.Level.Should().Be(AccessLevel.ReadWrite);
    }

    [Fact]
    public void DirectoryAccessRequest_Should_AllowExecuteLevel()
    {
        // Arrange & Act
        var request = new DirectoryAccessRequest(
            Path: "/test/path",
            Level: AccessLevel.Execute,
            Justification: "Running commands"
        );

        // Assert
        request.Level.Should().Be(AccessLevel.Execute);
    }

    [Fact]
    public void DirectoryAccessRequest_Should_AcceptEmptyJustification()
    {
        // Arrange & Act
        var request = new DirectoryAccessRequest(
            Path: "/test/path",
            Level: AccessLevel.ReadOnly,
            Justification: string.Empty
        );

        // Assert
        request.Justification.Should().BeEmpty();
    }

    [Fact]
    public void DirectoryAccessRequest_Should_AcceptRelativePath()
    {
        // Arrange & Act
        var request = new DirectoryAccessRequest(
            Path: "./relative/path",
            Level: AccessLevel.ReadOnly,
            Justification: "Test relative path"
        );

        // Assert
        request.Path.Should().Be("./relative/path");
    }

    [Fact]
    public void DirectoryAccessRequest_Should_AcceptAbsolutePath()
    {
        // Arrange & Act
        var request = new DirectoryAccessRequest(
            Path: "/absolute/path",
            Level: AccessLevel.ReadWrite,
            Justification: "Test absolute path"
        );

        // Assert
        request.Path.Should().Be("/absolute/path");
    }
}
