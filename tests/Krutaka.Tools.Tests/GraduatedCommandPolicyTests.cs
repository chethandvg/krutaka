using System.Security;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Tests for <see cref="GraduatedCommandPolicy"/> - the v0.3.0 graduated command execution policy.
/// </summary>
public sealed class GraduatedCommandPolicyTests
{
    private readonly ICommandRiskClassifier _mockClassifier;
    private readonly ISecurityPolicy _mockSecurityPolicy;
    private readonly IAccessPolicyEngine _mockPolicyEngine;
    private readonly CommandPolicyOptions _defaultOptions;

    public GraduatedCommandPolicyTests()
    {
        _mockClassifier = Substitute.For<ICommandRiskClassifier>();
        _mockSecurityPolicy = Substitute.For<ISecurityPolicy>();
        _mockPolicyEngine = Substitute.For<IAccessPolicyEngine>();
        _defaultOptions = new CommandPolicyOptions
        {
            ModerateAutoApproveInTrustedDirs = true
        };
    }

    #region Constructor Tests

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenClassifierIsNull()
    {
        // Act
        var act = () => new GraduatedCommandPolicy(
            null!,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("classifier");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenSecurityPolicyIsNull()
    {
        // Act
        var act = () => new GraduatedCommandPolicy(
            _mockClassifier,
            null!,
            _mockPolicyEngine,
            _defaultOptions);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("securityPolicy");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenOptionsIsNull()
    {
        // Act
        var act = () => new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("options");
    }

    [Fact]
    public void Constructor_Should_AcceptNullPolicyEngine()
    {
        // Act
        var act = () => new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            null,
            _defaultOptions);

        // Assert
        act.Should().NotThrow();
    }

    #endregion

    #region EvaluateAsync - Null Request Tests

    [Fact]
    public async Task EvaluateAsync_Should_ThrowArgumentNullException_WhenRequestIsNull()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var act = () => policy.EvaluateAsync(null!, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    #endregion

    #region Pre-check Security Validation Tests

    [Fact]
    public async Task EvaluateAsync_Should_CallSecurityPolicyValidateCommand_BeforeClassification()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "git",
            new[] { "status" },
            "/test",
            "Test command");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        // Verify ValidateCommand was called with correct parameters
        _mockSecurityPolicy.Received(1).ValidateCommand(
            request.Executable,
            Arg.Is<IEnumerable<string>>(args => args.SequenceEqual(request.Arguments)),
            Arg.Any<CorrelationContext?>());
    }

    [Fact]
    public async Task EvaluateAsync_Should_ThrowSecurityException_WhenMetacharacterDetected()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "git",
            new[] { "status; rm -rf /" },
            "/test",
            "Malicious command");

        // Configure security policy to throw on metacharacter
        _mockSecurityPolicy
            .When(x => x.ValidateCommand(
                Arg.Any<string>(),
                Arg.Any<IEnumerable<string>>(),
                Arg.Any<CorrelationContext?>()))
            .Do(_ => throw new SecurityException("Shell metacharacter detected"));

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var act = () => policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityException>()
            .WithMessage("*metacharacter*");

        // Verify classifier was NOT called (pre-check failed first)
        _mockClassifier.DidNotReceive().Classify(Arg.Any<CommandExecutionRequest>());
    }

    [Fact]
    public async Task EvaluateAsync_Should_ThrowSecurityException_WhenBlocklistedCommandDetected()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "powershell",
            new[] { "-Command", "Get-Process" },
            "/test",
            "Blocked command");

        // Configure security policy to throw on blocklisted command
        _mockSecurityPolicy
            .When(x => x.ValidateCommand(
                Arg.Any<string>(),
                Arg.Any<IEnumerable<string>>(),
                Arg.Any<CorrelationContext?>()))
            .Do(_ => throw new SecurityException("Blocklisted executable"));

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var act = () => policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityException>()
            .WithMessage("*Blocklisted*");

        // Verify classifier was NOT called
        _mockClassifier.DidNotReceive().Classify(Arg.Any<CommandExecutionRequest>());
    }

    #endregion

    #region Safe Tier Tests

    [Fact]
    public async Task EvaluateAsync_Should_AutoApprove_WhenCommandClassifiedAsSafe()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "git",
            new[] { "status" },
            "/test",
            "Check git status");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.Should().NotBeNull();
        decision.IsApproved.Should().BeTrue();
        decision.RequiresApproval.Should().BeFalse();
        decision.IsDenied.Should().BeFalse();
        decision.Tier.Should().Be(CommandRiskTier.Safe);
        decision.Reason.Should().Contain("Auto-approved");
        decision.Reason.Should().Contain("Safe tier");
    }

    [Theory]
    [InlineData("git", "log")]
    [InlineData("dotnet", "--version")]
    [InlineData("cat", "file.txt")]
    public async Task EvaluateAsync_Should_AutoApproveSafeCommands_WithoutCheckingDirectoryTrust(
        string executable,
        string argument)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { argument },
            "/untrusted/path",
            "Safe read operation");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.IsApproved.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Safe);

        // Verify policy engine was NOT consulted for Safe tier
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    #endregion

    #region Moderate Tier Tests - Trusted Directory

    [Fact]
    public async Task EvaluateAsync_Should_AutoApproveModerate_WhenInTrustedDirectory()
    {
        // Arrange
        var workingDir = "/trusted/project";
        var request = new CommandExecutionRequest(
            "dotnet",
            new[] { "build" },
            workingDir,
            "Build project");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Configure policy engine to grant access (trusted directory)
        _mockPolicyEngine.EvaluateAsync(
            Arg.Is<DirectoryAccessRequest>(r => r.Path == workingDir),
            Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Grant(workingDir, AccessLevel.Execute));

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.IsApproved.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
        decision.Reason.Should().Contain("Auto-approved");
        decision.Reason.Should().Contain("Moderate tier");
        decision.Reason.Should().Contain("trusted directory");
    }

    [Fact]
    public async Task EvaluateAsync_Should_PassCorrectAccessRequest_ToPolicyEngine()
    {
        // Arrange
        var workingDir = "/test/dir";
        var request = new CommandExecutionRequest(
            "npm",
            new[] { "run", "test" },
            workingDir,
            "Run tests");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        _mockPolicyEngine.EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Grant(workingDir, AccessLevel.Execute));

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        await _mockPolicyEngine.Received(1).EvaluateAsync(
            Arg.Is<DirectoryAccessRequest>(r =>
                r.Path == workingDir &&
                r.Level == AccessLevel.Execute &&
                r.Justification.Contains("npm")),
            Arg.Any<CancellationToken>());
    }

    #endregion

    #region Moderate Tier Tests - Untrusted Directory

    [Fact]
    public async Task EvaluateAsync_Should_RequireApprovalForModerate_WhenInUntrustedDirectory()
    {
        // Arrange
        var workingDir = "/untrusted/dir";
        var request = new CommandExecutionRequest(
            "git",
            new[] { "commit", "-m", "message" },
            workingDir,
            "Commit changes");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Configure policy engine to deny access (untrusted directory)
        _mockPolicyEngine.EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Deny("Not in trusted zone"));

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
        decision.Reason.Should().Contain("Requires approval");
        decision.Reason.Should().Contain("Moderate tier");
        decision.Reason.Should().Contain("untrusted directory");
    }

    [Fact]
    public async Task EvaluateAsync_Should_RequireApprovalForModerate_WhenAccessRequiresApproval()
    {
        // Arrange
        var workingDir = "/requires/approval";
        var request = new CommandExecutionRequest(
            "python",
            new[] { "script.py" },
            workingDir,
            "Run script");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Configure policy engine to require approval
        _mockPolicyEngine.EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(AccessDecision.RequireApproval(workingDir));

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.RequiresApproval.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
    }

    #endregion

    #region Moderate Tier Tests - Configuration

    [Fact]
    public async Task EvaluateAsync_Should_RequireApprovalForModerate_WhenAutoApprovalDisabled()
    {
        // Arrange
        var workingDir = "/trusted/dir";
        var request = new CommandExecutionRequest(
            "dotnet",
            new[] { "test" },
            workingDir,
            "Run tests");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Configure policy engine to grant access
        _mockPolicyEngine.EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Grant(workingDir, AccessLevel.Execute));

        // Disable auto-approval feature via configuration
        var options = new CommandPolicyOptions
        {
            ModerateAutoApproveInTrustedDirs = false
        };

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            options);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.RequiresApproval.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
        decision.Reason.Should().Contain("auto-approval disabled by configuration");

        // Verify policy engine was NOT consulted when feature is disabled
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    #endregion

    #region Moderate Tier Tests - Null Policy Engine

    [Fact]
    public async Task EvaluateAsync_Should_RequireApprovalForModerate_WhenPolicyEngineIsNull()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "mkdir",
            new[] { "test-dir" },
            "/some/path",
            "Create directory");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Create policy with null policy engine
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            null, // No policy engine
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.RequiresApproval.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
        decision.Reason.Should().Contain("no access policy engine available");
    }

    #endregion

    #region Moderate Tier Tests - Missing Working Directory

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task EvaluateAsync_Should_RequireApprovalForModerate_WhenWorkingDirectoryIsNullOrEmpty(
        string? workingDir)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "python",
            new[] { "script.py" },
            workingDir,
            "Run script");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.RequiresApproval.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
        decision.Reason.Should().Contain("no working directory specified");

        // Verify policy engine was NOT consulted when working dir is missing
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    #endregion

    #region Elevated Tier Tests

    [Fact]
    public async Task EvaluateAsync_Should_RequireApproval_WhenCommandClassifiedAsElevated()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "git",
            new[] { "push", "origin", "main" },
            "/test",
            "Push changes");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Elevated);

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
        decision.Tier.Should().Be(CommandRiskTier.Elevated);
        decision.Reason.Should().Contain("Requires approval");
        decision.Reason.Should().Contain("Elevated tier");
    }

    [Fact]
    public async Task EvaluateAsync_Should_RequireApprovalForElevated_EvenInTrustedDirectory()
    {
        // Arrange
        var workingDir = "/trusted/project";
        var request = new CommandExecutionRequest(
            "npm",
            new[] { "install", "lodash" },
            workingDir,
            "Install dependency");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Elevated);

        // Configure policy engine to grant access (trusted directory)
        _mockPolicyEngine.EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Grant(workingDir, AccessLevel.Execute));

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.RequiresApproval.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Elevated);

        // Verify policy engine was NOT consulted for Elevated tier
        // (directory trust does not affect Elevated tier)
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("git", "pull")]
    [InlineData("dotnet", "publish")]
    [InlineData("pip", "install", "numpy")]
    public async Task EvaluateAsync_Should_AlwaysRequireApprovalForElevated_RegardlessOfConfig(
        string executable,
        params string[] arguments)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            arguments,
            "/anywhere",
            "Elevated operation");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Elevated);

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.RequiresApproval.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Elevated);
    }

    #endregion

    #region Dangerous Tier Tests

    [Fact]
    public async Task EvaluateAsync_Should_ThrowSecurityException_WhenCommandClassifiedAsDangerous()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "format",
            new[] { "C:" },
            "/test",
            "Format drive");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Dangerous);

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var act = () => policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityException>()
            .WithMessage("*Dangerous tier*");
    }

    [Fact]
    public async Task EvaluateAsync_Should_ThrowSecurityExceptionForDangerous_AsDefenseInDepth()
    {
        // Arrange
        // This tests the scenario where a command somehow passes pre-check
        // but is classified as Dangerous (should not happen in practice,
        // but we have defense-in-depth to handle it)
        var request = new CommandExecutionRequest(
            "unknown-executable",
            new[] { "arg" },
            "/test",
            "Unknown command");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Dangerous);

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var act = () => policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<SecurityException>()
            .WithMessage("*security boundary*");
    }

    #endregion

    #region CancellationToken Tests

    [Fact]
    public async Task EvaluateAsync_Should_PropagateCancellationToken_ToPolicyEngine()
    {
        // Arrange
        var workingDir = "/test";
        var request = new CommandExecutionRequest(
            "dotnet",
            new[] { "build" },
            workingDir,
            "Build");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        using var cts = new CancellationTokenSource();
        var token = cts.Token;

        _mockPolicyEngine.EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            token)
            .Returns(AccessDecision.Grant(workingDir, AccessLevel.Execute));

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        await policy.EvaluateAsync(request, token);

        // Assert
        await _mockPolicyEngine.Received(1).EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            token);
    }

    [Fact]
    public async Task EvaluateAsync_Should_RespectCancellation_WhenTokenCancelled()
    {
        // Arrange
        var workingDir = "/test";
        var request = new CommandExecutionRequest(
            "python",
            new[] { "script.py" },
            workingDir,
            "Run script");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync(); // Cancel immediately

        _mockPolicyEngine.EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var token = callInfo.Arg<CancellationToken>();
                token.ThrowIfCancellationRequested();
                return Task.FromResult(AccessDecision.Grant(workingDir, AccessLevel.Execute));
            });

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        var act = () => policy.EvaluateAsync(request, cts.Token);

        // Assert
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    #endregion

    #region Integration-Style Tests

    [Fact]
    public async Task EvaluateAsync_Should_FollowCorrectEvaluationSequence()
    {
        // Arrange
        var callOrder = new List<string>();
        var workingDir = "/test";

        var request = new CommandExecutionRequest(
            "git",
            new[] { "commit" },
            workingDir,
            "Commit");

        // Track call order
        _mockSecurityPolicy
            .When(x => x.ValidateCommand(
                Arg.Any<string>(),
                Arg.Any<IEnumerable<string>>(),
                Arg.Any<CorrelationContext?>()))
            .Do(_ => callOrder.Add("SecurityPolicy.ValidateCommand"));

        _mockClassifier.Classify(request)
            .Returns(callInfo =>
            {
                callOrder.Add("Classifier.Classify");
                return CommandRiskTier.Moderate;
            });

        _mockPolicyEngine.EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                callOrder.Add("PolicyEngine.EvaluateAsync");
                return Task.FromResult(AccessDecision.Grant(workingDir, AccessLevel.Execute));
            });

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            _defaultOptions);

        // Act
        await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        callOrder.Should().HaveCount(3);
        callOrder[0].Should().Be("SecurityPolicy.ValidateCommand");
        callOrder[1].Should().Be("Classifier.Classify");
        callOrder[2].Should().Be("PolicyEngine.EvaluateAsync");
    }

    #endregion
}
