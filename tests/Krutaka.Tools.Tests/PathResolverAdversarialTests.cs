using System.Security;
using FluentAssertions;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Adversarial tests for PathResolver - attempts to bypass path validation through
/// Alternate Data Streams (ADS), reserved device names, device path prefixes, and
/// other path manipulation attacks.
/// </summary>
public sealed class PathResolverAdversarialTests
{
    #region Alternate Data Stream (ADS) Attacks

    [Theory]
    [InlineData("file.txt:hidden")]
    [InlineData("document.doc:stream")]
    [InlineData("data.bin:secret:$DATA")]
    [InlineData(@"C:\temp\file.txt:hidden")]
    [InlineData(@"C:\temp\folder\doc.pdf:stream")]
    public void Should_BlockAlternateDataStream(string pathWithAds)
    {
        // Act
        var action = () => PathResolver.ResolveToFinalTarget(pathWithAds);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*Alternate Data Stream*");
    }

    [Fact]
    public void Should_BlockADS_WithExoticStreamName()
    {
        // Arrange
        var pathWithAds = @"C:\temp\file.txt:Zone.Identifier:$DATA";

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(pathWithAds);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*Alternate Data Stream*");
    }

    [Fact]
    public void Should_AllowDriveLetterColon()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Drive letters are Windows-specific
        }

        // Arrange - valid Windows path with drive letter
        var validPath = @"C:\temp\file.txt";

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(validPath);

        // Assert - should not throw (drive letter colon is allowed)
        action.Should().NotThrow();
    }

    #endregion

    #region Reserved Device Name Attacks

    [Theory]
    [InlineData("CON")]
    [InlineData("PRN")]
    [InlineData("AUX")]
    [InlineData("NUL")]
    [InlineData("COM1")]
    [InlineData("COM9")]
    [InlineData("LPT1")]
    [InlineData("LPT9")]
    public void Should_BlockReservedDeviceName_AsFilename(string deviceName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Reserved device names are Windows-specific
        }

        // Arrange
        var path = Path.Combine(@"C:\temp", deviceName);

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(path);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage($"*{deviceName}*");
    }

    [Theory]
    [InlineData("CON.txt")]
    [InlineData("PRN.log")]
    [InlineData("NUL.dat")]
    [InlineData("COM1.config")]
    [InlineData("LPT1.pdf")]
    public void Should_BlockReservedDeviceName_WithExtension(string filename)
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Reserved device names are Windows-specific
        }

        // Arrange
        var path = Path.Combine(@"C:\temp", filename);

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(path);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*reserved device name*");
    }

    [Theory]
    [InlineData(@"C:\CON\file.txt")]
    [InlineData(@"C:\temp\NUL\data.bin")]
    [InlineData(@"C:\projects\PRN\output.log")]
    public void Should_BlockReservedDeviceName_InIntermediateDirectory(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Reserved device names are Windows-specific
        }

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(path);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*reserved device name*");
    }

    [Theory]
    [InlineData("CON.")]
    [InlineData("NUL ")]
    [InlineData("PRN.  ")]
    public void Should_BlockReservedDeviceName_WithTrailingDotsSpaces(string filename)
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Reserved device names are Windows-specific
        }

        // Arrange - Windows normalizes trailing dots and spaces
        var path = Path.Combine(@"C:\temp", filename);

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(path);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*reserved device name*");
    }

    [Theory]
    [InlineData("con")]
    [InlineData("CoM1")]
    [InlineData("LpT5")]
    public void Should_BlockReservedDeviceName_CaseInsensitive(string filename)
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Reserved device names are Windows-specific
        }

        ArgumentNullException.ThrowIfNull(filename);

        // Arrange
        var path = Path.Combine(@"C:\temp", filename);

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(path);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*reserved device name*");
    }

    [Fact]
    public void Should_NotBlockNonDeviceName()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Windows-specific test
        }

        // Arrange - PRNG is not a device name
        var path = Path.Combine(@"C:\temp", "PRNG");

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(path);

        // Assert - should not throw
        action.Should().NotThrow();
    }

    #endregion

    #region Device Path Prefix Attacks

    [Theory]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\.\C:")]
    [InlineData(@"\\.\COM1")]
    [InlineData(@"\\.\mailslot\test")]
    public void Should_BlockDevicePathPrefix_DotSlash(string devicePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Device paths are Windows-specific
        }

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(devicePath);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*Device path prefix*");
    }

    [Theory]
    [InlineData(@"\\?\C:\temp")]
    [InlineData(@"\\?\Volume{guid}\")]
    [InlineData(@"\\?\UNC\server\share")]
    public void Should_BlockDevicePathPrefix_QuestionMark(string verbatimPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Verbatim paths are Windows-specific
        }

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(verbatimPath);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*Device path prefix*");
    }

    [Theory]
    [InlineData(@"\\.\\PhysicalDrive0")] // Mixed case backslash
    [InlineData(@"//./C:")] // Forward slashes
    public void Should_BlockDevicePathPrefix_Variations(string devicePath)
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Device paths are Windows-specific
        }

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(devicePath);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*Device path prefix*");
    }

    #endregion

    #region Deeply Nested Path Handling

    [Fact]
    public void Should_HandleDeeplyNestedPath_WithoutCrash()
    {
        // Arrange - create a path with many nested directories
        var basePath = OperatingSystem.IsWindows() ? @"C:\temp" : "/tmp";
        var segments = new List<string> { basePath };
        for (int i = 0; i < 50; i++)
        {
            segments.Add($"level{i}");
        }

        segments.Add("file.txt");
        var deepPath = Path.Combine(segments.ToArray());

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(deepPath);

        // Assert - should not crash, may succeed or fail gracefully
        try
        {
            var result = action();
            result.Should().NotBeNullOrWhiteSpace();
        }
        catch (PathTooLongException)
        {
            // Acceptable - path too long
        }
        catch (SecurityException)
        {
            // Acceptable - security validation failed
        }
        catch (IOException)
        {
            // Acceptable - I/O error
        }
    }

    [Fact]
    public void Should_HandlePathExceedingMaxLength()
    {
        // Arrange - create a path exceeding Windows MAX_PATH (260 chars)
        var basePath = OperatingSystem.IsWindows() ? @"C:\temp" : "/tmp";
        var longSegment = new string('a', 100);
        var longPath = Path.Combine(basePath, longSegment, longSegment, longSegment);

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(longPath);

        // Assert - should handle gracefully
        try
        {
            var result = action();
            result.Should().NotBeNullOrWhiteSpace();
        }
        catch (PathTooLongException)
        {
            // Acceptable to fail with PathTooLongException
        }
        catch (SecurityException)
        {
            // Acceptable - security validation failed
        }
        catch (IOException)
        {
            // Acceptable - I/O error
        }
    }

    #endregion

    #region Edge Cases and Validation

    [Fact]
    public void Should_ThrowOnNullPath()
    {
        // Act
        var action = () => PathResolver.ResolveToFinalTarget(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_ThrowOnEmptyPath()
    {
        // Act
        var action = () => PathResolver.ResolveToFinalTarget(string.Empty);

        // Assert
        action.Should().Throw<ArgumentException>()
            .WithMessage("*cannot be empty*");
    }

    [Fact]
    public void Should_ThrowOnWhitespacePath()
    {
        // Act
        var action = () => PathResolver.ResolveToFinalTarget("   ");

        // Assert
        action.Should().Throw<ArgumentException>()
            .WithMessage("*cannot be empty*");
    }

    [Fact]
    public void Should_HandlePathWithMultipleSlashes()
    {
        // Arrange
        var pathWithSlashes = OperatingSystem.IsWindows()
            ? @"C:\temp\\\\folder\\\file.txt"
            : "/tmp////folder///file.txt";

        // Act
        var action = () => PathResolver.ResolveToFinalTarget(pathWithSlashes);

        // Assert - should normalize or handle gracefully
        action.Should().NotThrow();
    }

    #endregion
}
