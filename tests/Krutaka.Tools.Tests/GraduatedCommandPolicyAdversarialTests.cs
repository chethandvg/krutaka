using System.Security;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Adversarial tests for GraduatedCommandPolicy - attempts to bypass graduated command
/// execution controls through tier manipulation, directory trust abuse, and edge cases.
/// These tests verify that the policy engine maintains security boundaries under attack.
/// </summary>
public sealed class GraduatedCommandPolicyAdversarialTests
{
    private readonly ICommandRiskClassifier _mockClassifier;
    private readonly ISecurityPolicy _mockSecurityPolicy;
    private readonly IAccessPolicyEngine _mockPolicyEngine;
    private readonly CommandPolicyOptions _defaultOptions;

    public GraduatedCommandPolicyAdversarialTests()
    {
        _mockClassifier = Substitute.For<ICommandRiskClassifier>();
        _mockSecurityPolicy = Substitute.For<ISecurityPolicy>();
        _mockPolicyEngine = Substitute.For<IAccessPolicyEngine>();
        _defaultOptions = new CommandPolicyOptions
        {
            ModerateAutoApproveInTrustedDirs = true
        };
    }

    #region Moderate Command Directory Trust Bypass Attempts

    [Fact]
    public async Task Should_RequireApproval_ForModerateCommandOutsideTrustedDirectory()
    {
        // Arrange - Moderate command in untrusted directory
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("git", new[] { "commit" }, "/untrusted", "Commit");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        var directoryRequest = new DirectoryAccessRequest("/untrusted", AccessLevel.ReadWrite, "commit");
        var directoryDecision = AccessDecision.RequireApproval("/untrusted");
        _mockPolicyEngine.EvaluateAsync(
            Arg.Is<DirectoryAccessRequest>(r => r.Path == "/untrusted"),
            Arg.Any<CancellationToken>())
            .Returns(directoryDecision);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Should require approval
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public async Task Should_AutoApprove_ForModerateCommandInsideTrustedDirectory()
    {
        // Arrange - Moderate command in trusted directory
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("git", new[] { "commit" }, "/trusted", "Commit");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        var directoryRequest = new DirectoryAccessRequest("/trusted", AccessLevel.ReadWrite, "commit");
        var directoryDecision = AccessDecision.Grant("/trusted", AccessLevel.ReadWrite);
        _mockPolicyEngine.EvaluateAsync(
            Arg.Is<DirectoryAccessRequest>(r => r.Path == "/trusted"),
            Arg.Any<CancellationToken>())
            .Returns(directoryDecision);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Should auto-approve
        decision.RequiresApproval.Should().BeFalse();
        decision.IsApproved.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public async Task Should_RequireApproval_ForElevatedCommandEvenInTrustedDirectory()
    {
        // Arrange - Elevated tier overrides directory trust
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("git", new[] { "push" }, "/trusted", "Push");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Elevated);

        // Even if directory is trusted, Elevated tier requires approval
        var directoryDecision = AccessDecision.Grant("/trusted", AccessLevel.ReadWrite);
        _mockPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(directoryDecision);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Tier overrides directory trust
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
        decision.Tier.Should().Be(CommandRiskTier.Elevated);
    }

    #endregion

    #region Security Pre-Check Enforcement

    [Fact]
    public async Task Should_ThrowSecurityException_ForSafeCommandWithShellMetacharacters()
    {
        // Arrange - Security check runs BEFORE tier classification
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("git", new[] { "status|ls" }, "/test", "Meta");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        // Security policy throws on metacharacters
        _mockSecurityPolicy
            .When(x => x.ValidateCommand("git", Arg.Is<IReadOnlyList<string>>(args => args.Contains("status|ls")), Arg.Any<CorrelationContext>()))
            .Do(_ => throw new SecurityException("Shell metacharacters detected"));

        // Act
        var action = async () => await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Security exception should propagate (pre-check failed)
        await action.Should().ThrowAsync<SecurityException>()
            .WithMessage("*metacharacters*");
    }

    [Fact]
    public async Task Should_ThrowSecurityException_ForModerateCommandWithBlocklistedExecutable()
    {
        // Arrange - Blocklist check in pre-check
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("powershell", new[] { "ls" }, "/test", "Blocked");

        // Security policy throws on blocklisted executable
        _mockSecurityPolicy
            .When(x => x.ValidateCommand("powershell", Arg.Any<IReadOnlyList<string>>(), Arg.Any<CorrelationContext>()))
            .Do(_ => throw new SecurityException("Blocked executable: powershell"));

        // Act
        var action = async () => await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Should fail security pre-check
        await action.Should().ThrowAsync<SecurityException>()
            .WithMessage("*Blocked executable*");
    }

    #endregion

    #region Config Override Tests

    [Fact]
    public async Task Should_RespectConfigOverride_WhenPromotingCommandToSafe()
    {
        // This test verifies that tier overrides from config are used correctly
        // Note: The classifier would need to be configured with the override rules
        // This test uses a mock classifier that returns the overridden tier

        // Arrange - Custom executable promoted to Safe via config
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            null, // No policy engine needed for Safe tier
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("cargo", new[] { "check" }, "/test", "Cargo check");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Should auto-approve (Safe tier)
        decision.RequiresApproval.Should().BeFalse();
        decision.IsApproved.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Safe);
    }

    [Fact]
    public async Task Should_NotAllowConfigOverride_ForBlocklistedCommands()
    {
        // This test verifies that blocklisted commands cannot be promoted via config
        // The CommandTierConfigValidator should reject such configs at startup
        // Here we test that even if the classifier returns non-Dangerous, the security pre-check blocks it

        // Arrange - Attempt to override powershell (should fail in pre-check)
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            null,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("powershell", new[] { "echo" }, "/test", "Blocked");

        // Security policy blocks powershell before classification
        _mockSecurityPolicy
            .When(x => x.ValidateCommand("powershell", Arg.Any<IReadOnlyList<string>>(), Arg.Any<CorrelationContext>()))
            .Do(_ => throw new SecurityException("Blocked executable: powershell"));

        // Act
        var action = async () => await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Should throw regardless of tier override attempt
        await action.Should().ThrowAsync<SecurityException>();
    }

    #endregion

    #region Null Policy Engine Behavior

    [Fact]
    public async Task Should_RequireApproval_ForModerateCommandWhenPolicyEngineIsNull()
    {
        // Arrange - No policy engine → cannot evaluate directory trust
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            null, // No policy engine
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("git", new[] { "commit" }, "/test", "Commit");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Should require approval (cannot verify directory trust)
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public async Task Should_AutoApprove_ForSafeCommandEvenWhenPolicyEngineIsNull()
    {
        // Arrange - Safe tier doesn't require policy engine
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            null, // No policy engine
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("git", new[] { "status" }, "/test", "Status");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Should auto-approve
        decision.RequiresApproval.Should().BeFalse();
        decision.IsApproved.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion

    #region Thread Safety Tests

    [Fact]
    public async Task Should_HandleRapidSequentialCommands_ThreadSafely()
    {
        // Arrange - Test concurrent evaluation
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        // Create multiple requests
        var requests = Enumerable.Range(0, 20).Select(i =>
            new CommandExecutionRequest("git", new[] { i % 2 == 0 ? "status" : "commit" }, "/test", $"Cmd {i}")
        ).ToArray();

        // Configure classifier to alternate between Safe and Moderate
        _mockClassifier.Classify(Arg.Any<CommandExecutionRequest>())
            .Returns(callInfo =>
            {
                var req = callInfo.Arg<CommandExecutionRequest>();
                return req.Arguments[0] == "status" ? CommandRiskTier.Safe : CommandRiskTier.Moderate;
            });

        // Configure policy engine to grant all Moderate requests
        _mockPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var req = callInfo.Arg<DirectoryAccessRequest>();
                return AccessDecision.Grant(req.Path, AccessLevel.ReadWrite);
            });

        // Act - Evaluate all requests concurrently
        var tasks = requests.Select(req => policy.EvaluateAsync(req, CancellationToken.None));
        var decisions = await Task.WhenAll(tasks);

        // Assert - All decisions should be valid
        decisions.Should().HaveCount(20);
        decisions.Should().AllSatisfy(d =>
        {
            d.Should().NotBeNull();
            d.Tier.Should().BeOneOf(CommandRiskTier.Safe, CommandRiskTier.Moderate);
        });
    }

    #endregion

    #region Combined Directory Access and Tier Evaluation

    [Fact]
    public async Task Should_EvaluateDirectoryAccess_ForModerateCommands()
    {
        // Arrange - Verify directory access is checked for Moderate tier
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("git", new[] { "add" }, "/project", "Add files");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        var directoryDecision = AccessDecision.Grant("/project", AccessLevel.ReadWrite);
        _mockPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(directoryDecision);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.IsApproved.Should().BeTrue();
        decision.RequiresApproval.Should().BeFalse();

        // Verify directory access was evaluated
        await _mockPolicyEngine.Received(1).EvaluateAsync(
            Arg.Is<DirectoryAccessRequest>(r =>
                r.Path == "/project" &&
                r.Level == AccessLevel.Execute), // Moderate commands request Execute level
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_NotEvaluateDirectoryAccess_ForSafeCommands()
    {
        // Arrange - Safe tier doesn't need directory evaluation
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("git", new[] { "status" }, "/project", "Status");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.IsApproved.Should().BeTrue();
        decision.RequiresApproval.Should().BeFalse();

        // Verify directory access was NOT evaluated
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_NotEvaluateDirectoryAccess_ForElevatedCommands()
    {
        // Arrange - Elevated tier doesn't use directory trust
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("npm", new[] { "publish" }, "/project", "Publish");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Elevated);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();

        // Verify directory access was NOT evaluated
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    #endregion

    #region Edge Cases and Validation

    [Fact]
    public async Task Should_ThrowArgumentNullException_WhenRequestIsNull()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        // Act
        var action = async () => await policy.EvaluateAsync(null!, CancellationToken.None);

        // Assert
        await action.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task Should_DenyDangerousCommand_EvenInTrustedDirectory()
    {
        // Arrange - Dangerous tier always throws SecurityException
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest("unknown-tool", new[] { "arg" }, "/trusted", "Unknown");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Dangerous);

        // Act & Assert - Should throw SecurityException
        var action = async () => await policy.EvaluateAsync(request, CancellationToken.None);
        await action.Should().ThrowAsync<SecurityException>()
            .WithMessage("*Dangerous tier*");
    }

    [Fact]
    public async Task Should_HandleModerateAutoApproveDisabled_ViaConfig()
    {
        // Arrange - Config disables auto-approve for Moderate in trusted dirs
        var options = new CommandPolicyOptions
        {
            ModerateAutoApproveInTrustedDirs = false
        };

        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            options);

        var request = new CommandExecutionRequest("git", new[] { "commit" }, "/trusted", "Commit");
        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        var directoryDecision = AccessDecision.Grant("/trusted", AccessLevel.ReadWrite);
        _mockPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(directoryDecision);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Should require approval (auto-approve disabled)
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
    }

    #endregion
}
