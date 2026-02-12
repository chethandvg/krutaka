using System.Security;
using FluentAssertions;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

public sealed class PathResolverTests : IDisposable
{
    private readonly string _testRoot;

    public PathResolverTests()
    {
        _testRoot = TestDirectoryHelper.GetTestDirectory("pathresolver");
        Directory.CreateDirectory(_testRoot);
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
    }

    #region Normal Path Tests

    [Fact]
    public void Should_ResolveNormalPath_Unchanged()
    {
        // Arrange
        var normalFile = Path.Combine(_testRoot, "test.txt");
        File.WriteAllText(normalFile, "content");

        // Act
        var resolved = PathResolver.ResolveToFinalTarget(normalFile);

        // Assert
        resolved.Should().Be(Path.GetFullPath(normalFile));
    }

    [Fact]
    public void Should_ResolveRelativePath_ToAbsolute()
    {
        // Arrange
        var relativePath = Path.Combine(".", "test.txt");
        
        // Act
        var resolved = PathResolver.ResolveToFinalTarget(relativePath);

        // Assert
        resolved.Should().Be(Path.GetFullPath(relativePath));
    }

    [Fact]
    public void Should_ResolveNonExistentPath_WithValidParent()
    {
        // Arrange
        var nonExistentPath = Path.Combine(_testRoot, "does-not-exist.txt");

        // Act
        var resolved = PathResolver.ResolveToFinalTarget(nonExistentPath);

        // Assert
        resolved.Should().Be(Path.GetFullPath(nonExistentPath));
    }

    #endregion

    #region Alternate Data Stream (ADS) Tests

    [Theory]
    [InlineData("C:\\test\\file.txt:hidden")]
    [InlineData("C:\\test\\file.txt:stream:$DATA")]
    [InlineData("file.txt:ads")]
    public void Should_BlockAlternateDataStream(string pathWithAds)
    {
        // Act
        var action = () => PathResolver.ResolveToFinalTarget(pathWithAds);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*Alternate Data Streams*");
    }

    [Fact]
    public void Should_AllowNormalDriveLetter()
    {
        // Arrange - drive letter with colon at position 1 is valid
        var normalPath = Path.Combine(_testRoot, "normal.txt");
        File.WriteAllText(normalPath, "content");

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(normalPath);

        // Assert
        action.Should().NotThrow();
    }

    #endregion

    #region Reserved Device Name Tests

    [Theory]
    [InlineData("CON")]
    [InlineData("con")]
    [InlineData("PRN")]
    [InlineData("prn")]
    [InlineData("AUX")]
    [InlineData("NUL")]
    [InlineData("COM1")]
    [InlineData("COM9")]
    [InlineData("LPT1")]
    [InlineData("LPT9")]
    public void Should_BlockReservedDeviceName(string deviceName)
    {
        // Arrange
        var devicePath = Path.Combine(_testRoot, deviceName);

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(devicePath);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*Reserved device names*");
    }

    [Theory]
    [InlineData("CON.txt")]
    [InlineData("PRN.log")]
    [InlineData("NUL.dat")]
    [InlineData("COM1.config")]
    public void Should_BlockReservedDeviceName_WithExtension(string deviceName)
    {
        // Arrange
        var devicePath = Path.Combine(_testRoot, deviceName);

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(devicePath);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*Reserved device names*");
    }

    [Fact]
    public void Should_AllowNormalFilename_SimilarToDeviceName()
    {
        // Arrange
        var normalFile = Path.Combine(_testRoot, "console.txt");
        File.WriteAllText(normalFile, "content");

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(normalFile);

        // Assert
        action.Should().NotThrow();
    }

    #endregion

    #region Device Path Prefix Tests

    [Theory]
    [InlineData(@"\\.\C:\test")]
    [InlineData(@"\\?\C:\test")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\?\Volume{12345678-1234-1234-1234-123456789012}\")]
    public void Should_BlockDevicePathPrefix(string devicePath)
    {
        // Act
        var action = () => PathResolver.ResolveToFinalTarget(devicePath);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*Device path prefixes*");
    }

    #endregion

    #region Symlink and Junction Tests

    [Fact]
    public void Should_ResolveSymlink_ToFinalTarget()
    {
        // Skip on non-Windows or if symlink creation fails
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            // Arrange
            var targetDir = Path.Combine(_testRoot, "target");
            Directory.CreateDirectory(targetDir);
            
            var targetFile = Path.Combine(targetDir, "real.txt");
            File.WriteAllText(targetFile, "content");

            var linkDir = Path.Combine(_testRoot, "link");
            
            // Create symlink (requires admin or developer mode on Windows)
            Directory.CreateSymbolicLink(linkDir, targetDir);

            var linkFile = Path.Combine(linkDir, "real.txt");

            // Act
            var resolved = PathResolver.ResolveToFinalTarget(linkFile);

            // Assert
            resolved.Should().Be(Path.GetFullPath(targetFile));
        }
        catch (UnauthorizedAccessException)
        {
            // Symlink creation requires elevated privileges or developer mode
            // Skip test if we don't have permission
            return;
        }
        catch (IOException)
        {
            // Symlink might not be supported on this system
            return;
        }
    }

    [Fact]
    public void Should_ResolveNonExistentPath_WhenParentIsSymlink()
    {
        // Skip on non-Windows or if symlink creation fails
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            // Arrange
            var targetDir = Path.Combine(_testRoot, "target");
            Directory.CreateDirectory(targetDir);

            var linkDir = Path.Combine(_testRoot, "link");
            Directory.CreateSymbolicLink(linkDir, targetDir);

            var nonExistentInLink = Path.Combine(linkDir, "new-file.txt");

            // Act
            var resolved = PathResolver.ResolveToFinalTarget(nonExistentInLink);

            // Assert
            var expectedTarget = Path.Combine(Path.GetFullPath(targetDir), "new-file.txt");
            resolved.Should().Be(expectedTarget);
        }
        catch (UnauthorizedAccessException)
        {
            // Skip if we don't have symlink creation permission
            return;
        }
        catch (IOException)
        {
            // Symlink might not be supported
            return;
        }
    }

    #endregion

    #region Circular Symlink Tests

    [Fact]
    public void Should_DetectCircularSymlink()
    {
        // Skip on non-Windows or if symlink creation fails
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            // Arrange
            var link1 = Path.Combine(_testRoot, "link1");
            var link2 = Path.Combine(_testRoot, "link2");

            // Create circular symlinks: link1 -> link2 -> link1
            Directory.CreateSymbolicLink(link1, link2);
            Directory.CreateSymbolicLink(link2, link1);

            // Act
            var action = () => PathResolver.ResolveToFinalTarget(link1);

            // Assert
            action.Should().Throw<IOException>()
                .WithMessage("*Circular symlink*");
        }
        catch (UnauthorizedAccessException)
        {
            // Skip if we don't have symlink creation permission
            return;
        }
        catch (IOException ex) when (!ex.Message.Contains("Circular", StringComparison.OrdinalIgnoreCase))
        {
            // Symlink might not be supported - skip test
            return;
        }
    }

    #endregion

    #region Edge Case Tests

    [Fact]
    public void Should_ThrowArgumentNullException_WhenPathIsNull()
    {
        // Act
        var action = () => PathResolver.ResolveToFinalTarget(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public void Should_ThrowArgumentException_WhenPathIsEmpty(string emptyPath)
    {
        // Act
        var action = () => PathResolver.ResolveToFinalTarget(emptyPath);

        // Assert
        action.Should().Throw<ArgumentException>()
            .WithMessage("*cannot be empty*");
    }

    [Fact]
    public void Should_ThrowSecurityException_WhenPathIsInvalid()
    {
        // Arrange - path with invalid characters
        var invalidPath = "C:\\test\0invalid.txt"; // null byte

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(invalidPath);

        // Assert
        action.Should().Throw<SecurityException>();
    }

    #endregion
}
