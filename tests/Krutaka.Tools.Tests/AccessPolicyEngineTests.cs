using System.Security;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using NSubstitute;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Tests for LayeredAccessPolicyEngine - the four-layer directory access policy engine.
/// Tests cover Layer 1 (Hard Deny), Layer 2 (Configurable Allow), Layer 3 (Session Grants), 
/// Layer 4 (Heuristics), and layering behavior (denies cannot be overridden).
/// </summary>
public sealed class AccessPolicyEngineTests : IDisposable
{
    private readonly string _testRoot;
    private readonly string _ceilingDirectory;
    private readonly IFileOperations _fileOperations;

    public AccessPolicyEngineTests()
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
        if (Directory.Exists(_testRoot))
        {
            Directory.Delete(_testRoot, recursive: true);
        }
    }

    #region Layer 1: Hard Deny Tests

    [Fact]
    public async Task Should_DenyAccess_WhenPathIsSystemDirectory()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows — Windows directory resolved via Environment
        }

        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var request = new DirectoryAccessRequest(windowsDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_DenyAccess_WhenPathIsProgramFiles()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows — Program Files resolved via Environment
        }

        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var request = new DirectoryAccessRequest(Path.Combine(programFiles, "SomeApp"), AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_DenyAccess_WhenPathIsAppData()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows
        }

        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var request = new DirectoryAccessRequest(Path.Combine(appDataPath, "test"), AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*AppData*");
    }

    [Fact]
    public async Task Should_DenyAccess_WhenPathIsKrutakaConfigDirectory()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var krutakaConfigPath = Path.Combine(userProfile, ".krutaka");
        var request = new DirectoryAccessRequest(krutakaConfigPath, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*Krutaka configuration*");
    }

    [Fact]
    public async Task Should_DenyAccess_WhenPathIsAboveCeiling()
    {
        // Arrange
        var ceiling = _testRoot; // Ceiling is the test root
        var engine = new LayeredAccessPolicyEngine(_fileOperations, ceiling, [], null);
        var parentPath = Path.GetDirectoryName(_testRoot)!; // Parent of test root
        var request = new DirectoryAccessRequest(parentPath, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*ceiling*");
    }

    [Fact]
    public async Task Should_DenyAccess_WhenPathIsUNCPath()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows - UNC paths are Windows-specific
        }

        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(@"\\server\share\path", AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().ContainMatch("*UNC*");
    }

    #endregion

    #region Layer 2: Configurable Allow Tests

    [Fact]
    public async Task Should_GrantAccess_WhenPathMatchesGlobPattern()
    {
        // Arrange
        var testSubDir = Path.Combine(_testRoot, "projects");
        Directory.CreateDirectory(testSubDir);
        var globPattern = Path.Combine(_testRoot, "**"); // Match everything under test root
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [globPattern], null);
        var request = new DirectoryAccessRequest(testSubDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Granted);
        decision.Granted.Should().BeTrue();
        decision.ScopedPath.Should().NotBeNull();
        decision.GrantedLevel.Should().Be(AccessLevel.ReadOnly);
    }

    [Fact]
    public async Task Should_PassThrough_WhenPathDoesNotMatchGlobPattern()
    {
        // Arrange
        var testSubDir = Path.Combine(_testRoot, "projects");
        Directory.CreateDirectory(testSubDir);
        var globPattern = Path.Combine(_testRoot, "other", "**"); // Different path
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [globPattern], null);
        var request = new DirectoryAccessRequest(testSubDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        // Should pass through to Layer 4 (requires approval since no session grant)
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
    }

    [Fact]
    public async Task Should_PassThrough_WhenNoGlobPatternsConfigured()
    {
        // Arrange
        var testSubDir = Path.Combine(_testRoot, "projects");
        Directory.CreateDirectory(testSubDir);
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(testSubDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        // Should pass through to Layer 4 (requires approval)
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
    }

    [Fact]
    public async Task Should_NotMatchSiblingPaths_WithGlobPattern()
    {
        // Arrange - Test that "Proj/**" doesn't match "Proj2/..."
        var testProj = Path.Combine(_testRoot, "Proj");
        var testProj2 = Path.Combine(_testRoot, "Proj2");
        Directory.CreateDirectory(testProj);
        Directory.CreateDirectory(testProj2);
        
        var globPattern = Path.Combine(_testRoot, "Proj", "**");
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [globPattern], null);
        var request = new DirectoryAccessRequest(testProj2, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        // Should NOT match because Proj2 is a sibling, not a descendant of Proj
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
    }

    #endregion

    #region Layer 3: Session Grants Tests

    [Fact]
    public async Task Should_GrantAccess_WhenSessionGrantExists()
    {
        // Arrange
        var testSubDir = Path.Combine(_testRoot, "projects");
        Directory.CreateDirectory(testSubDir);
        
        var mockSessionStore = Substitute.For<ISessionAccessStore>();
        var canonicalPath = Path.GetFullPath(testSubDir);
        mockSessionStore.IsGrantedAsync(canonicalPath, AccessLevel.ReadOnly, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], mockSessionStore);
        var request = new DirectoryAccessRequest(testSubDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Granted);
        decision.Granted.Should().BeTrue();
        decision.ScopedPath.Should().NotBeNull();
        decision.GrantedLevel.Should().Be(AccessLevel.ReadOnly);
    }

    [Fact]
    public async Task Should_PassThrough_WhenNoSessionGrantExists()
    {
        // Arrange
        var testSubDir = Path.Combine(_testRoot, "projects");
        Directory.CreateDirectory(testSubDir);
        
        var mockSessionStore = Substitute.For<ISessionAccessStore>();
        mockSessionStore.IsGrantedAsync(Arg.Any<string>(), Arg.Any<AccessLevel>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(false));

        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], mockSessionStore);
        var request = new DirectoryAccessRequest(testSubDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        // Should pass through to Layer 4 (requires approval)
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
    }

    [Fact]
    public async Task Should_PassThrough_WhenNoSessionStoreConfigured()
    {
        // Arrange
        var testSubDir = Path.Combine(_testRoot, "projects");
        Directory.CreateDirectory(testSubDir);
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(testSubDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        // Should pass through to Layer 4 (requires approval)
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
    }

    #endregion

    #region Layer 4: Heuristic Tests

    [Fact]
    public async Task Should_RequireApproval_ForCrossVolumeAccess()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Cross-volume detection is Windows-specific
        }

        var ceilingOnC = @"C:\temp";
        var pathOnD = @"D:\Projects\MyApp";
        var engine = new LayeredAccessPolicyEngine(_fileOperations, ceilingOnC, [], null);
        var request = new DirectoryAccessRequest(pathOnD, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
    }

    [Fact]
    public async Task Should_RequireApproval_ForVeryDeepPath()
    {
        // Arrange
        var deepPath = Path.Combine(_testRoot, "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k");
        Directory.CreateDirectory(deepPath);
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(deepPath, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
    }

    [Fact]
    public async Task Should_RequireApproval_ForNormalPathNotMatchedByEarlierLayers()
    {
        // Arrange
        var testSubDir = Path.Combine(_testRoot, "projects");
        Directory.CreateDirectory(testSubDir);
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest(testSubDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
    }

    #endregion

    #region Layering Behavior Tests

    [Fact]
    public async Task Should_DenyInLayer1_CannotBeOverriddenByLayer2GlobPattern()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows — Windows directory resolved via Environment
        }

        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var globPattern = windowsDir + @"\**"; // Try to auto-grant system directory
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [globPattern], null);
        var request = new DirectoryAccessRequest(Path.Combine(windowsDir, "System32"), AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_DenyInLayer1_CannotBeOverriddenByLayer3SessionGrant()
    {
        // Arrange
        if (!OperatingSystem.IsWindows())
        {
            return; // Skip on non-Windows — Windows directory resolved via Environment
        }

        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var mockSessionStore = Substitute.For<ISessionAccessStore>();
        mockSessionStore.IsGrantedAsync(Arg.Any<string>(), Arg.Any<AccessLevel>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true)); // Pretend session grant exists

        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], mockSessionStore);
        var request = new DirectoryAccessRequest(Path.Combine(windowsDir, "System32"), AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    #endregion

    #region Decision Caching Tests

    [Fact]
    public async Task Should_OnlyCheckSessionStoreOnce_ForSameCanonicalPathInSingleEvaluation()
    {
        // Arrange
        var testSubDir = Path.Combine(_testRoot, "projects");
        Directory.CreateDirectory(testSubDir);
        
        var mockSessionStore = Substitute.For<ISessionAccessStore>();
        var canonicalPath = Path.GetFullPath(testSubDir);
        mockSessionStore.IsGrantedAsync(canonicalPath, AccessLevel.ReadOnly, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(true));

        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], mockSessionStore);
        var request = new DirectoryAccessRequest(testSubDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Granted);
        
        // Session store should only be called once per evaluation
        await mockSessionStore.Received(1).IsGrantedAsync(canonicalPath, AccessLevel.ReadOnly, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_ReevaluateOnSecondCall_BecauseCacheIsClearedPerEvaluation()
    {
        // Arrange
        var testSubDir = Path.Combine(_testRoot, "projects");
        Directory.CreateDirectory(testSubDir);
        
        var mockSessionStore = Substitute.For<ISessionAccessStore>();
        var canonicalPath = Path.GetFullPath(testSubDir);
        mockSessionStore.IsGrantedAsync(canonicalPath, AccessLevel.ReadOnly, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(false)); // No session grant

        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], mockSessionStore);
        var request = new DirectoryAccessRequest(testSubDir, AccessLevel.ReadOnly, "test");

        // Act
        var decision1 = await engine.EvaluateAsync(request, CancellationToken.None);
        var decision2 = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        // Both should require approval (no grant)
        decision1.Outcome.Should().Be(AccessOutcome.RequiresApproval);
        decision2.Outcome.Should().Be(AccessOutcome.RequiresApproval);
        
        // Session store should be called twice (cache cleared between evaluations)
        await mockSessionStore.Received(2).IsGrantedAsync(canonicalPath, AccessLevel.ReadOnly, Arg.Any<CancellationToken>());
    }

    #endregion

    #region Edge Cases and Error Handling

    [Fact]
    public async Task Should_HandleInvalidPath_GracefullyWithDenial()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var request = new DirectoryAccessRequest("", AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_HandleNullRequest_ThrowsArgumentNullException()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);

        // Act
        Func<Task> act = async () => await engine.EvaluateAsync(null!, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public void Should_ThrowArgumentNullException_WhenFileOperationsIsNull()
    {
        // Act
        Action act = () => _ = new LayeredAccessPolicyEngine(null!, _ceilingDirectory, [], null);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_ThrowArgumentNullException_WhenCeilingDirectoryIsNull()
    {
        // Act
        Action act = () => _ = new LayeredAccessPolicyEngine(_fileOperations, null!, [], null);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_ThrowArgumentNullException_WhenAutoGrantPatternsIsNull()
    {
        // Act
        Action act = () => _ = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, null!, null);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    #endregion

    #region Audit Log Tamper-proofing Tests

    [Fact]
    public async Task Should_DenyAccess_WhenPathIsAuditLogDirectory()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var auditLogDir = Path.Combine(userProfile, ".krutaka", "logs");
        var request = new DirectoryAccessRequest(auditLogDir, AccessLevel.ReadWrite, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_DenyAccess_WhenPathIsUnderAuditLogDirectory()
    {
        // Arrange
        var engine = new LayeredAccessPolicyEngine(_fileOperations, _ceilingDirectory, [], null);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var auditLogFile = Path.Combine(userProfile, ".krutaka", "logs", "audit-2026-01-01.json");
        var request = new DirectoryAccessRequest(auditLogFile, AccessLevel.ReadOnly, "test");

        // Act
        var decision = await engine.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
    }

    #endregion
}
