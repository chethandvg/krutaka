using FluentAssertions;
using Krutaka.Tools;
using Microsoft.Extensions.Logging.Abstractions;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Adversarial tests for GlobPatternValidator - attempts to configure overly broad
/// or malicious glob patterns that would grant excessive directory access.
/// These tests verify that dangerous patterns are rejected at startup.
/// </summary>
public sealed class GlobPatternValidatorTests_Adversarial
{
    private readonly GlobPatternValidator _validator;

    public GlobPatternValidatorTests_Adversarial()
    {
        _validator = new GlobPatternValidator(NullLogger<GlobPatternValidator>.Instance);
    }

    #region Overly Broad Pattern Attacks

    [Fact]
    public void Should_RejectPattern_DriveRootWithWildcard()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Drive-specific test
        }

        // Arrange - catastrophically broad pattern
        var patterns = new[] { @"C:\**" };
        var ceiling = @"C:\Users\test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*segment*");
    }

    [Fact]
    public void Should_RejectPattern_OnlyDoubleWildcard()
    {
        // Arrange - matches everything
        var patterns = new[] { "**" };
        var ceiling = OperatingSystem.IsWindows() ? @"C:\Users\test" : "/home/test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*absolute*");
    }

    [Fact]
    public void Should_RejectPattern_SingleWildcard()
    {
        // Arrange - matches everything in current directory
        var patterns = new[] { "*" };
        var ceiling = OperatingSystem.IsWindows() ? @"C:\Users\test" : "/home/test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
    }

    [Fact]
    public void Should_RejectPattern_TwoSegments()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Drive-specific test
        }

        // Arrange - too broad (only 2 segments)
        var patterns = new[] { @"C:\Users\**" };
        var ceiling = @"C:\Users\test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*3*segment*");
    }

    [Fact]
    public void Should_WarnOnPattern_ThreeSegments()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Drive-specific test
        }

        // Arrange - borderline broad (3 segments - minimum)
        var patterns = new[] { @"C:\Users\test\**" };
        var ceiling = @"C:\Users\test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeTrue(); // Valid but with warning
        result.Warnings.Should().NotBeEmpty();
        result.Warnings.Should().ContainMatch("*broad*");
    }

    #endregion

    #region Relative Traversal Attacks

    [Fact]
    public void Should_RejectPattern_RelativeTraversal()
    {
        // Arrange - attempts to escape via ..
        var patterns = new[] { @"..\..\..\**" };
        var ceiling = OperatingSystem.IsWindows() ? @"C:\Users\test" : "/home/test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
    }

    [Fact]
    public void Should_RejectPattern_RelativePath()
    {
        // Arrange - relative paths without root
        var patterns = new[] { @"subfolder\**" };
        var ceiling = OperatingSystem.IsWindows() ? @"C:\Users\test" : "/home/test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
    }

    [Fact]
    public void Should_RejectPattern_CurrentDirectory()
    {
        // Arrange - current directory reference
        var patterns = new[] { @".\**" };
        var ceiling = OperatingSystem.IsWindows() ? @"C:\Users\test" : "/home/test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
    }

    #endregion

    #region Blocked Directory Patterns

    [Fact]
    public void Should_RejectPattern_ContainingSystemDirectory()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Windows-specific test
        }

        // Arrange - pattern includes blocked system directory
        var patterns = new[] { @"C:\Windows\System32\**" };
        var ceiling = @"C:\";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*Windows*");
    }

    [Fact]
    public void Should_RejectPattern_ContainingProgramFiles()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Windows-specific test
        }

        // Arrange - pattern includes blocked directory
        var patterns = new[] { @"C:\Program Files\MyApp\**" };
        var ceiling = @"C:\";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*Program Files*");
    }

    [Fact]
    public void Should_RejectPattern_ContainingAppData()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Windows-specific test
        }

        // Arrange - pattern under AppData
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var patterns = new[] { Path.Combine(appData, "MyApp", "**") };
        var ceiling = Path.GetDirectoryName(appData) ?? @"C:\Users\test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*AppData*");
    }

    #endregion

    #region Outside Ceiling Attacks

    [Fact]
    public void Should_RejectPattern_OutsideCeiling()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Drive-specific test
        }

        // Arrange - pattern on different drive than ceiling
        var patterns = new[] { @"D:\Backup\**" };
        var ceiling = @"C:\Users\test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*ceiling*");
    }

    [Fact]
    public void Should_RejectPattern_AboveCeiling()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Windows path test
        }

        // Arrange - pattern parent of ceiling
        var patterns = new[] { @"C:\Users\**" };
        var ceiling = @"C:\Users\test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*ceiling*");
    }

    #endregion

    #region Null/Empty Pattern Handling

    [Fact]
    public void Should_RejectEmptyPattern()
    {
        // Arrange
        var patterns = new[] { string.Empty };
        var ceiling = OperatingSystem.IsWindows() ? @"C:\Users\test" : "/home/test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*empty*");
    }

    [Fact]
    public void Should_RejectWhitespacePattern()
    {
        // Arrange
        var patterns = new[] { "   " };
        var ceiling = OperatingSystem.IsWindows() ? @"C:\Users\test" : "/home/test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*empty*");
    }

    [Fact]
    public void Should_HandleNullInPatternArray()
    {
        // Arrange - array with null element
        var patterns = new[] { @"C:\Users\test\Projects\**", null! };
        var ceiling = @"C:\Users\test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
    }

    #endregion

    #region Multiple Pattern Validation

    [Fact]
    public void Should_RejectAllInvalid_WhenMultiplePatternsInvalid()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Windows-specific test
        }

        // Arrange - multiple bad patterns
        var patterns = new[]
        {
            @"C:\**",              // Too broad
            @"**",                 // No root
            @"..\..\..\**",       // Relative traversal
            @"C:\Windows\**"      // Blocked directory
        };
        var ceiling = @"C:\Users\test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().HaveCountGreaterOrEqualTo(4); // One error per pattern
    }

    [Fact]
    public void Should_RejectMixed_WhenAnyPatternInvalid()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Windows-specific test
        }

        // Arrange - mix of valid and invalid
        var patterns = new[]
        {
            @"C:\Users\test\Projects\**",  // Valid
            @"C:\**"                       // Invalid (too broad)
        };
        var ceiling = @"C:\Users\test";

        // Act
        var result = _validator.ValidatePatterns(patterns, ceiling);

        // Assert
        result.IsValid.Should().BeFalse(); // Overall invalid due to one bad pattern
        result.Errors.Should().NotBeEmpty();
    }

    #endregion

    #region Argument Validation

    [Fact]
    public void Should_ThrowOnNullPatternArray()
    {
        // Arrange
        var ceiling = OperatingSystem.IsWindows() ? @"C:\Users\test" : "/home/test";

        // Act
        var action = () => _validator.ValidatePatterns(null!, ceiling);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_ThrowOnNullCeiling()
    {
        // Arrange
        var patterns = new[] { @"C:\Users\test\**" };

        // Act
        var action = () => _validator.ValidatePatterns(patterns, null!);

        // Assert
        action.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Should_ThrowOnEmptyCeiling()
    {
        // Arrange
        var patterns = new[] { @"C:\Users\test\**" };

        // Act
        var action = () => _validator.ValidatePatterns(patterns, string.Empty);

        // Assert
        action.Should().Throw<ArgumentException>();
    }

    #endregion
}
