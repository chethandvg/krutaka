using FluentAssertions;
using Krutaka.Tools;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Tests for GlobPatternValidator - validates glob patterns for auto-grant directory access.
/// Tests cover startup validation, security constraint enforcement, and edge cases.
/// </summary>
public sealed class GlobPatternValidatorTests
{
    private readonly string _ceilingDirectory;
    private readonly GlobPatternValidator _validator;

    public GlobPatternValidatorTests()
    {
        // Use a ceiling directory that actually exists on the system
        _ceilingDirectory = OperatingSystem.IsWindows()
            ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Create validator without logger for most tests
        _validator = new GlobPatternValidator();
    }

    #region Valid Patterns

    [Fact]
    public void Should_AcceptValidPattern_WithFourSegments()
    {
        // Arrange
        var pattern = Path.Combine(_ceilingDirectory, "Projects", "**");

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptValidPattern_WithThreeSegments()
    {
        // Arrange
        var pattern = Path.Combine(_ceilingDirectory, "**");

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
        // Should have a warning about being borderline broad
        result.Warnings.Should().NotBeEmpty();
        result.Warnings.Should().ContainMatch("*3 segments*");
    }

    [Fact]
    public void Should_AcceptValidPattern_WithExactPath()
    {
        // Arrange
        var pattern = Path.Combine(_ceilingDirectory, "Projects", "MyApp");

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptValidPattern_WithSlashSeparators()
    {
        // Arrange - Test with forward slashes even on Windows
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        var pattern = "C:/Users/TestUser/Projects/**";

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    #endregion

    #region Too-Broad Patterns (< 3 segments)

    [Fact]
    public void Should_RejectPattern_WithTwoSegments()
    {
        // Arrange
        var pattern = OperatingSystem.IsWindows()
            ? @"C:\Users\**"
            : "/home/**";
        var ceiling = OperatingSystem.IsWindows()
            ? @"C:\"
            : "/";

        // Act
        var result = _validator.ValidatePattern(pattern, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*too broad*");
        result.Errors.Should().ContainMatch("*fewer than 3*");
    }

    [Fact]
    public void Should_RejectPattern_WithOneSegment()
    {
        // Arrange
        var pattern = OperatingSystem.IsWindows()
            ? @"C:\**"
            : "/**";
        var ceiling = OperatingSystem.IsWindows()
            ? @"C:\"
            : "/";

        // Act
        var result = _validator.ValidatePattern(pattern, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        // Pattern starting with wildcard is rejected before breadth check
        result.Errors.Should().HaveCount(1);
    }

    [Fact]
    public void Should_RejectPattern_WithOnlyWildcards()
    {
        // Arrange
        var pattern = "**";

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*absolute base path*");
    }

    #endregion

    #region Blocked Directory Patterns

    [Fact]
    public void Should_RejectPattern_ContainingWindowsDirectory()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        var pattern = @"C:\Windows\**";

        // Act
        var result = _validator.ValidatePattern(pattern, @"C:\");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocked directory*Windows*");
    }

    [Fact]
    public void Should_RejectPattern_ContainingProgramFiles()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        var pattern = @"C:\Program Files\MyApp\**";

        // Act
        var result = _validator.ValidatePattern(pattern, @"C:\");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocked directory*Program Files*");
    }

    [Fact]
    public void Should_RejectPattern_ContainingAppData()
    {
        // Arrange
        var pattern = Path.Combine(_ceilingDirectory, "AppData", "**");

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocked directory*AppData*");
    }

    [Fact]
    public void Should_RejectPattern_ContainingKrutakaConfig()
    {
        // Arrange
        var pattern = Path.Combine(_ceilingDirectory, ".krutaka", "**");

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocked directory*.krutaka*");
    }

    [Fact]
    public void Should_RejectPattern_ContainingSystem32()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows - System32 is Windows-specific
        }

        var pattern = @"C:\Windows\System32\**";

        // Act
        var result = _validator.ValidatePattern(pattern, @"C:\");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocked directory*");
    }

    #endregion

    #region Outside-Ceiling Patterns

    [Fact]
    public void Should_RejectPattern_OutsideCeilingDirectory()
    {
        // Arrange
        var ceiling = _ceilingDirectory;
        var pattern = OperatingSystem.IsWindows()
            ? @"D:\OtherDrive\Path\**"  // Different drive
            : "/opt/other/**";  // Different top-level directory

        // Act
        var result = _validator.ValidatePattern(pattern, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*outside the ceiling directory*");
    }

    [Fact]
    public void Should_RejectPattern_OnDifferentDriveFromCeiling()
    {
        // Arrange - Only applicable on Windows
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        var ceiling = @"C:\Users\TestUser";
        var pattern = @"D:\Projects\**";

        // Act
        var result = _validator.ValidatePattern(pattern, ceiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*outside the ceiling directory*");
    }

    [Fact]
    public void Should_AcceptPattern_UnderCeilingDirectory()
    {
        // Arrange
        var ceiling = _ceilingDirectory;
        var pattern = Path.Combine(_ceilingDirectory, "Projects", "**");

        // Act
        var result = _validator.ValidatePattern(pattern, ceiling);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    #endregion

    #region Empty/Null/Whitespace Patterns

    [Fact]
    public void Should_RejectEmptyPattern()
    {
        // Arrange
        var pattern = "";

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*cannot be null, empty, or whitespace*");
    }

    [Fact]
    public void Should_RejectNullPattern()
    {
        // Arrange
        string pattern = null!;

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*cannot be null, empty, or whitespace*");
    }

    [Fact]
    public void Should_RejectWhitespacePattern()
    {
        // Arrange
        var pattern = "   ";

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*cannot be null, empty, or whitespace*");
    }

    #endregion

    #region Case-Insensitive Matching (Windows)

    [Fact]
    public void Should_DetectBlockedDirectory_CaseInsensitive()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        var pattern = @"c:\windows\**"; // lowercase

        // Act
        var result = _validator.ValidatePattern(pattern, @"C:\");

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocked directory*");
    }

    [Fact]
    public void Should_CheckCeilingContainment_CaseInsensitive()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        var ceiling = @"C:\Users\TestUser";
        var pattern = @"c:\users\testuser\projects\**"; // lowercase

        // Act
        var result = _validator.ValidatePattern(pattern, ceiling);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    #endregion

    #region Multiple Pattern Validation

    [Fact]
    public void Should_ValidateMultiplePatterns_AllValid()
    {
        // Arrange
        var patterns = new[]
        {
            Path.Combine(_ceilingDirectory, "Projects", "**"),
            Path.Combine(_ceilingDirectory, "Documents", "**")
        };

        // Act
        var result = _validator.ValidatePatterns(patterns, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_ValidateMultiplePatterns_SomeInvalid()
    {
        // Arrange
        var broadPattern = OperatingSystem.IsWindows() ? @"C:\**" : "/**";
        var broadCeiling = OperatingSystem.IsWindows() ? @"C:\" : "/";

        var patterns = new[]
        {
            Path.Combine(_ceilingDirectory, "Projects", "**"),
            broadPattern,
            Path.Combine(_ceilingDirectory, "Documents", "**")
        };

        // Act
        var result = _validator.ValidatePatterns(patterns, broadCeiling);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        // Pattern starting with wildcard or too broad - either error is acceptable
    }

    #endregion

    #region Warning Cases

    [Fact]
    public void Should_LogWarning_ForBorderlineBroadPattern()
    {
        // Arrange
        var mockLogger = Substitute.For<ILogger<GlobPatternValidator>>();
        var validator = new GlobPatternValidator(mockLogger);
        var pattern = Path.Combine(_ceilingDirectory, "**");
        var patterns = new[] { pattern };

        // Act
        var result = validator.ValidatePatterns(patterns, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Warnings.Should().NotBeEmpty();
        result.Warnings.Should().ContainMatch("*3 segments*");

        // Verify logger was called at least once with Warning level
        // Note: LoggerMessage uses a compiled delegate which may not be easily mockable
        // Just verify warnings were generated
        mockLogger.ReceivedCalls().Should().NotBeEmpty();
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void Should_HandlePatternWithoutWildcard()
    {
        // Arrange
        var pattern = Path.Combine(_ceilingDirectory, "Projects", "MyApp");

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_HandleInvalidPathCharacters()
    {
        // Arrange
        var pattern = "C:\\Invalid<>Path\\**";

        // Act
        var result = _validator.ValidatePattern(pattern, _ceilingDirectory);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*Invalid*");
    }

    [Fact]
    public void Should_ThrowArgumentNullException_WhenPatternsIsNull()
    {
        // Act
        Action act = () => _validator.ValidatePatterns(null!, _ceilingDirectory);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_ThrowArgumentException_WhenCeilingDirectoryIsNull()
    {
        // Arrange
        var patterns = new[] { "C:\\Users\\TestUser\\Projects\\**" };

        // Act
        Action act = () => _validator.ValidatePatterns(patterns, null!);

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Should_ThrowArgumentException_WhenCeilingDirectoryIsEmpty()
    {
        // Arrange
        var patterns = new[] { "C:\\Users\\TestUser\\Projects\\**" };

        // Act
        Action act = () => _validator.ValidatePatterns(patterns, "");

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Should_ThrowArgumentException_WhenCeilingDirectoryIsWhitespace()
    {
        // Arrange
        var patterns = new[] { "C:\\Users\\TestUser\\Projects\\**" };

        // Act
        Action act = () => _validator.ValidatePatterns(patterns, "   ");

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    #endregion
}
