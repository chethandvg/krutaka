using System.Security;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using NSubstitute;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Adversarial tests for LayeredAccessPolicyEngine - attempts to bypass security controls
/// through every known attack vector. These tests validate that the policy engine is resistant
/// to social engineering, path manipulation, and scope accumulation attacks.
/// </summary>
public sealed class AccessPolicyEngineAdversarialTests : IDisposable
{
    private readonly string _testRoot;
    private readonly string _ceilingDirectory;
    private readonly IFileOperations _fileOperations;

    public AccessPolicyEngineAdversarialTests()
    {
        // Create a unique test directory outside AppData to avoid security blocks
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        if (OperatingSystem.IsWindows())
        {
            _testRoot = Path.Combine(@"C:\temp", $"krutaka-test-{uniqueId}");
            _ceilingDirectory = @"C:\temp";
        }
        else
        {
            _testRoot = Path.Combine("/tmp", $"krutaka-test-{uniqueId}");
            _ceilingDirectory = "/tmp";
        }

        Directory.CreateDirectory(_testRoot);
        _fileOperations = new SafeFileOperations(null);
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
    }

    #region System Directory Bypass Attempts

    [Fact]
    public async Task Should_DenySystemDirectory_DespitePersuasiveJustification()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(
            @"C:\Windows\System32",
            AccessLevel.ReadOnly,
            "I need to read system configuration files to understand the environment for better assistance");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().NotBeEmpty();
        decision.DeniedReasons.Should().ContainMatch("*System32*");
    }

    [Fact]
    public async Task Should_DenyProgramFiles_WithAnyJustification()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(
            @"C:\Program Files\ImportantApp",
            AccessLevel.ReadOnly,
            "User explicitly requested access to this directory");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*Program Files*");
    }

    [Fact]
    public async Task Should_DenyAppData_WithPersuasiveReasoning()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var request = new DirectoryAccessRequest(
            Path.Combine(appDataPath, "UserConfig"),
            AccessLevel.ReadOnly,
            "Critical for reading user preferences to provide better assistance");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*AppData*");
    }

    [Fact]
    public async Task Should_DenyLocalAppData_WithUrgentJustification()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var request = new DirectoryAccessRequest(
            Path.Combine(localAppDataPath, "Temp"),
            AccessLevel.ReadOnly,
            "URGENT: User's critical data is stored here and must be accessed immediately");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*LocalAppData*");
    }

    [Fact]
    public async Task Should_DenyKrutakaConfigDirectory()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var krutakaPath = Path.Combine(userProfile, ".krutaka");
        var request = new DirectoryAccessRequest(
            krutakaPath,
            AccessLevel.ReadOnly,
            "Need to verify configuration settings");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*configuration*");
    }

    #endregion

    #region Ceiling Directory Enforcement

    [Fact]
    public async Task Should_DenyCeilingPlusOne_Directory()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        // Arrange - ceiling is C:\temp, try to access C:\
        var engine = new LayeredAccessPolicyEngine(_fileOperations, @"C:\temp", [], null);
        var request = new DirectoryAccessRequest(
            @"C:\",
            AccessLevel.ReadOnly,
            "Need to access root directory");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*ceiling*");
    }

    [Fact]
    public async Task Should_DenyParentOfCeiling()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        // Arrange - ceiling is C:\Users\test, try to access C:\Users
        var testCeiling = @"C:\Users\TestUser";
        var engine = new LayeredAccessPolicyEngine(_fileOperations, testCeiling, [], null);
        var request = new DirectoryAccessRequest(
            @"C:\Users",
            AccessLevel.ReadOnly,
            "Need to access parent directory");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*ceiling*");
    }

    #endregion

    #region Path Manipulation Attacks

    [Fact]
    public async Task Should_HandleUnicodeConfusables_InPath()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        // Unicode confusable: Cyrillic 'а' (U+0430) instead of Latin 'a'
        var confusablePath = Path.Combine(_testRoot, "dаta"); // 'а' is Cyrillic
        var request = new DirectoryAccessRequest(
            confusablePath,
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert - should process without crashing
        decision.Should().NotBeNull();
        decision.Outcome.Should().BeOneOf(AccessOutcome.RequiresApproval, AccessOutcome.Granted, AccessOutcome.Denied);
    }

    [Fact]
    public async Task Should_RejectNullByte_InPath()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var pathWithNull = _testRoot + "\0hidden";
        var request = new DirectoryAccessRequest(
            pathWithNull,
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        // Path validation should fail due to invalid characters
    }

    [Fact]
    public async Task Should_HandleMaxLengthPath_WithoutCrash()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        // Create a path > 260 characters (Windows MAX_PATH)
        var longSegment = new string('a', 100);
        var longPath = Path.Combine(_testRoot, longSegment, longSegment, longSegment);
        var request = new DirectoryAccessRequest(
            longPath,
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert - should handle gracefully without crash
        decision.Should().NotBeNull();
        decision.Outcome.Should().BeOneOf(AccessOutcome.RequiresApproval, AccessOutcome.Granted, AccessOutcome.Denied);
    }

    [Fact]
    public async Task Should_ReturnConsistentDecision_ForSamePathDifferentCasing()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Case sensitivity is platform-specific
        }

        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var path1 = Path.Combine(_testRoot, "MyFolder");
        var path2 = Path.Combine(_testRoot, "myfolder");
        var request1 = new DirectoryAccessRequest(path1, AccessLevel.ReadOnly, "test");
        var request2 = new DirectoryAccessRequest(path2, AccessLevel.ReadOnly, "test");

        // Act
        var decision1 = await engine.EvaluateAsync(request1, CancellationToken.None);
        var decision2 = await engine.EvaluateAsync(request2, CancellationToken.None);

        // Assert - decisions should be consistent (both granted or both denied)
        decision1.Outcome.Should().Be(decision2.Outcome);
        decision1.Granted.Should().Be(decision2.Granted);
    }

    [Fact]
    public async Task Should_AllowPathWithDotDot_WhenStillWithinRoot()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var subdir = Path.Combine(_testRoot, "sub1", "sub2");
        Directory.CreateDirectory(subdir);
        
        // Path with .. but still resolves within root
        var pathWithDotDot = Path.Combine(subdir, "..", "file.txt");
        var request = new DirectoryAccessRequest(
            pathWithDotDot,
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert - should require approval (not in auto-grant patterns) but not denied
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
        decision.Granted.Should().BeFalse(); // Not auto-granted, requires approval
    }

    [Fact]
    public async Task Should_DenyPathWithDotDot_WhenEscapingRoot()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        // Try to escape ceiling by going up multiple levels
        var escapePath = Path.Combine(_testRoot, "..", "..", "..", "Windows");
        var request = new DirectoryAccessRequest(
            escapePath,
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    #endregion

    #region Session Scope Accumulation Attacks

    [Fact]
    public async Task Should_LimitSessionGrants_ToMaximumCount()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore(maxConcurrentGrants: 3);

        // Grant 3 different directories (max)
        await store.GrantAccessAsync(
            Path.Combine(_testRoot, "dir1"),
            AccessLevel.ReadOnly,
            expiresAfter: null,
            justification: "test",
            GrantSource.User,
            CancellationToken.None);
        await store.GrantAccessAsync(
            Path.Combine(_testRoot, "dir2"),
            AccessLevel.ReadOnly,
            expiresAfter: null,
            justification: "test",
            GrantSource.User,
            CancellationToken.None);
        await store.GrantAccessAsync(
            Path.Combine(_testRoot, "dir3"),
            AccessLevel.ReadOnly,
            expiresAfter: null,
            justification: "test",
            GrantSource.User,
            CancellationToken.None);

        // Act - try to grant a 4th directory
        var action = async () => await store.GrantAccessAsync(
            Path.Combine(_testRoot, "dir4"),
            AccessLevel.ReadOnly,
            expiresAfter: null,
            justification: "test",
            GrantSource.User,
            CancellationToken.None);

        // Assert
        await action.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*maximum*");
    }

    [Fact]
    public async Task Should_PreventRapidFire_ScopeAccumulation()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore(maxConcurrentGrants: 5);

        // Act - try to rapidly grant many directories
        var successCount = 0;
        var tasks = new List<Task>();
        for (int i = 0; i < 10; i++)
        {
            var path = Path.Combine(_testRoot, $"rapid-{i}");
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    await store.GrantAccessAsync(
                        path,
                        AccessLevel.ReadOnly,
                        expiresAfter: null,
                        justification: "test",
                        GrantSource.User,
                        CancellationToken.None);
                    Interlocked.Increment(ref successCount);
                }
                catch (InvalidOperationException)
                {
                    // Expected when hitting max grants
                }
            }));
        }

        await Task.WhenAll(tasks);

        // Assert - should have hit the limit (max 5 successful grants)
        successCount.Should().BeLessOrEqualTo(5);
    }

    #endregion

    #region Cross-Volume Detection

    [Fact]
    public async Task Should_FlagCrossVolumeRequest_ForReview()
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Cross-volume is Windows-specific
        }

        // Arrange - ceiling on C:, request access to D:
        var engine = new LayeredAccessPolicyEngine(_fileOperations, @"C:\temp", [], null);
        var request = new DirectoryAccessRequest(
            @"D:\Projects",
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert - should require approval or be flagged
        // Layer 4 should detect cross-volume and flag for human review
        if (decision.Outcome == AccessOutcome.Denied)
        {
            // Acceptable if denied due to ceiling enforcement
            decision.DeniedReasons.Should().NotBeEmpty();
        }
        else
        {
            // Otherwise should require approval
            decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
        }
    }

    #endregion

    #region UNC Path Blocking

    [Fact]
    public async Task Should_BlockUNCPath_NetworkShare()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(
            @"\\server\share\folder",
            AccessLevel.ReadOnly,
            "Need to access network share");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert - UNC paths should be denied
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        // The error may be about ceiling or explicitly about UNC
        decision.DeniedReasons.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Should_BlockUNCPath_WithIPAddress()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(
            @"\\192.168.1.100\share\data",
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert - UNC paths should be denied
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        // The error may be about ceiling or explicitly about UNC
        decision.DeniedReasons.Should().NotBeEmpty();
    }

    #endregion

    #region Edge Cases

    [Fact]
    public async Task Should_HandleEmptyPath_Gracefully()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(
            string.Empty,
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_HandleWhitespacePath_Gracefully()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(
            "   ",
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_HandleRelativePath_Correctly()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(
            ".",
            AccessLevel.ReadOnly,
            "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert - should process without error
        decision.Should().NotBeNull();
        decision.Outcome.Should().BeOneOf(AccessOutcome.RequiresApproval, AccessOutcome.Granted, AccessOutcome.Denied);
    }

    #endregion
}
