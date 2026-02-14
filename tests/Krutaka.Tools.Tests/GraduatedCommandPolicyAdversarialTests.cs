using System.Security;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Adversarial tests for GraduatedCommandPolicy - attempts to bypass graduated command
/// execution through directory trust manipulation, tier promotion, and security boundary evasion.
/// These tests validate the policy engine's resistance to abuse and configuration tampering.
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

    #region Directory Trust Manipulation Tests

    [Fact]
    public async Task Should_RequireApproval_ForModerateCommand_OutsideTrustedDirectory()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["commit", "-m", "test"],
            "/untrusted/dir",
            "Moderate command in untrusted directory");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Mock policy engine to indicate directory is NOT trusted
        _mockPolicyEngine.EvaluateAsync(
            Arg.Is<DirectoryAccessRequest>(r =>
                r.Path == "/untrusted/dir" &&
                r.Level == AccessLevel.Execute),
            Arg.Any<CancellationToken>())
            .Returns(AccessDecision.RequireApproval("/untrusted/dir"));

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - should require approval because directory is not trusted
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public async Task Should_AutoApprove_ForModerateCommand_InsideTrustedDirectory()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["commit", "-m", "test"],
            "/trusted/dir",
            "Moderate command in trusted directory");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Mock policy engine to indicate directory IS trusted (auto-granted)
        _mockPolicyEngine.EvaluateAsync(
            Arg.Is<DirectoryAccessRequest>(r =>
                r.Path == "/trusted/dir" &&
                r.Level == AccessLevel.Execute),
            Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Grant(
                "/trusted/dir",
                AccessLevel.Execute,
                null));

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - should be auto-approved because directory is trusted
        decision.RequiresApproval.Should().BeFalse();
        decision.IsApproved.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public async Task Should_RequireApproval_ForElevatedCommand_EvenInTrustedDirectory()
    {
        // Arrange - tier overrides directory trust
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["push", "origin", "main"],
            "/trusted/dir",
            "Elevated command in trusted directory");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Elevated);

        // Mock policy engine to indicate directory IS trusted
        _mockPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Grant(
                "/trusted/dir",
                AccessLevel.ReadWrite,
                null));

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Elevated commands ALWAYS require approval, even in trusted dirs
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
        decision.Tier.Should().Be(CommandRiskTier.Elevated);
    }

    [Fact]
    public async Task Should_AutoApprove_ForSafeCommand_InAnyDirectory()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["status"],
            "/any/dir",
            "Safe command anywhere");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Safe commands are ALWAYS auto-approved
        decision.RequiresApproval.Should().BeFalse();
        decision.IsApproved.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Safe);
        
        // Policy engine should NOT be consulted for Safe tier
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_ThrowSecurityException_ForDangerousCommand_EvenInTrustedDirectory()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "unknownTool",
            ["arg"],
            "/trusted/dir",
            "Dangerous command in trusted directory");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Dangerous);

        // Act
        var action = async () => await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - Dangerous commands throw SecurityException (defense-in-depth)
        await action.Should().ThrowAsync<SecurityException>()
            .WithMessage("*Dangerous tier*cannot be executed*");
    }

    #endregion

    #region Security Pre-Check Integration Tests

    [Fact]
    public async Task Should_ThrowSecurityException_WhenSafeCommand_ContainsMetacharacters()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["status", "|", "grep", "modified"],
            "/test",
            "Safe command with pipe operator");

        // Mock security policy to throw on metacharacter detection
        _mockSecurityPolicy
            .When(x => x.ValidateCommand(request.Executable, request.Arguments, Arg.Any<CorrelationContext?>()))
            .Do(x => throw new SecurityException("Shell metacharacters detected"));

        // Act
        var action = async () => await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - SecurityException thrown BEFORE classification
        await action.Should().ThrowAsync<SecurityException>()
            .WithMessage("*metacharacters*");

        // Classifier should NOT be called if security pre-check fails
        _mockClassifier.DidNotReceive().Classify(Arg.Any<CommandExecutionRequest>());
    }

    [Fact]
    public async Task Should_ThrowSecurityException_WhenModerateCommand_ContainsPipeOperator()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["commit", "-m", "test && rm -rf /"],
            "/test",
            "Moderate command with command chaining");

        // Mock security policy to throw
        _mockSecurityPolicy
            .When(x => x.ValidateCommand(request.Executable, request.Arguments, Arg.Any<CorrelationContext?>()))
            .Do(x => throw new SecurityException("Shell metacharacters detected"));

        // Act
        var action = async () => await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - SecurityException thrown before tier evaluation
        await action.Should().ThrowAsync<SecurityException>();
    }

    [Fact]
    public async Task Should_ThrowSecurityException_ForBlocklistedExecutable_BeforeTierCheck()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "powershell",
            ["-Command", "Get-Process"],
            "/test",
            "Blocklisted executable");

        // Mock security policy to throw for blocklisted executable
        _mockSecurityPolicy
            .When(x => x.ValidateCommand(request.Executable, request.Arguments, Arg.Any<CorrelationContext?>()))
            .Do(x => throw new SecurityException("Blocked executable"));

        // Act
        var action = async () => await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - SecurityException thrown BEFORE classification
        await action.Should().ThrowAsync<SecurityException>()
            .WithMessage("*Blocked*");

        // Classifier should NOT be called
        _mockClassifier.DidNotReceive().Classify(Arg.Any<CommandExecutionRequest>());
    }

    [Fact]
    public async Task Should_ValidateCommand_BeforeClassification_Always()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["status"],
            "/test",
            "Normal command");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        // Act
        await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - SecurityPolicy.ValidateCommand called FIRST
        _mockSecurityPolicy.Received(1).ValidateCommand(
            request.Executable,
            request.Arguments,
            Arg.Any<CorrelationContext?>());
    }

    #endregion

    #region Configuration Tests

    [Fact]
    public async Task Should_RequireApproval_WhenAutoApprovalDisabledByConfiguration()
    {
        // Arrange - disable auto-approval for Moderate tier
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

        var request = new CommandExecutionRequest(
            "git",
            ["commit", "-m", "test"],
            "/trusted/dir",
            "Moderate command with auto-approve disabled");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - should require approval even if in trusted directory
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
        decision.Reason.Should().Contain("disabled by configuration");

        // Policy engine should NOT be consulted when feature is disabled
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_RequireApproval_WhenPolicyEngineIsNull()
    {
        // Arrange - no policy engine available
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            null, // No policy engine
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["commit", "-m", "test"],
            "/some/dir",
            "Moderate command without policy engine");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Act
        var decision = await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - should require approval when cannot determine trust
        decision.RequiresApproval.Should().BeTrue();
        decision.IsApproved.Should().BeFalse();
        decision.Reason.Should().Contain("no access policy engine");
    }

    [Fact]
    public async Task Should_HandlePolicyEngineException_Gracefully()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["commit", "-m", "test"],
            "/problematic/dir",
            "Directory that causes policy engine error");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        // Mock policy engine to throw exception
        _mockPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Throws(new InvalidOperationException("Policy engine error"));

        // Act
        var action = async () => await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - exception should propagate (fail-closed)
        await action.Should().ThrowAsync<InvalidOperationException>();
    }

    #endregion

    #region Thread Safety Tests

    [Fact]
    public async Task Should_HandleRapidSequentialEvaluations_Correctly()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var requests = Enumerable.Range(0, 50).Select(i => new CommandExecutionRequest(
            "git",
            ["status"],
            $"/test/dir{i}",
            $"Request {i}")).ToList();

        foreach (var req in requests)
        {
            _mockClassifier.Classify(req).Returns(CommandRiskTier.Safe);
        }

        // Act - evaluate many requests rapidly
        var tasks = requests.Select(r => policy.EvaluateAsync(r, CancellationToken.None));
        var decisions = await Task.WhenAll(tasks);

        // Assert - all should be auto-approved (Safe tier)
        decisions.Should().AllSatisfy(d =>
        {
            d.RequiresApproval.Should().BeFalse();
            d.IsApproved.Should().BeTrue();
            d.Tier.Should().Be(CommandRiskTier.Safe);
        });
    }

    [Fact]
    public async Task Should_HandleConcurrentEvaluations_ThreadSafely()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var requests = Enumerable.Range(0, 20).Select(i => new CommandExecutionRequest(
            "git",
            i % 2 == 0 ? new[] { "status" } : new[] { "push", "origin", "main" },
            "/test",
            $"Concurrent request {i}")).ToList();

        foreach (var req in requests)
        {
            var tier = req.Arguments[0] == "status" ? CommandRiskTier.Safe : CommandRiskTier.Elevated;
            _mockClassifier.Classify(req).Returns(tier);
        }

        // Act - evaluate concurrently from multiple threads
        var tasks = requests.Select(r => Task.Run(async () =>
            await policy.EvaluateAsync(r, CancellationToken.None)));

        var decisions = await Task.WhenAll(tasks);

        // Assert - decisions should be correct based on tier
        var safeDecisions = decisions.Where((d, i) => requests[i].Arguments[0] == "status");
        var elevatedDecisions = decisions.Where((d, i) => requests[i].Arguments[0] == "push");

        safeDecisions.Should().AllSatisfy(d =>
        {
            d.RequiresApproval.Should().BeFalse();
            d.IsApproved.Should().BeTrue();
        });

        elevatedDecisions.Should().AllSatisfy(d =>
        {
            d.RequiresApproval.Should().BeTrue();
            d.IsApproved.Should().BeFalse();
        });
    }

    #endregion

    #region Null and Argument Validation Tests

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
    public async Task Should_PassCorrelationContext_ToAllComponents()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["status"],
            "/test",
            "Correlation test");

        var correlationContext = new CorrelationContext(Guid.NewGuid());

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        // Act
        await policy.EvaluateAsync(request, CancellationToken.None, correlationContext);

        // Assert - correlation context passed to security policy
        _mockSecurityPolicy.Received(1).ValidateCommand(
            request.Executable,
            request.Arguments,
            correlationContext);
    }

    #endregion

    #region Integration with Access Policy Engine

    [Fact]
    public async Task Should_QueryPolicyEngine_WithCorrectParameters()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["commit", "-m", "test"],
            "/project/src",
            "Policy engine integration test");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Moderate);

        _mockPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(AccessDecision.RequireApproval("/project/src"));

        // Act
        await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - policy engine called with correct directory and access level
        await _mockPolicyEngine.Received(1).EvaluateAsync(
            Arg.Is<DirectoryAccessRequest>(r =>
                r.Path == "/project/src" &&
                r.Level == AccessLevel.Execute),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_NotQueryPolicyEngine_ForSafeTier()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["status"],
            "/test",
            "Safe tier - no policy engine query");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Safe);

        // Act
        await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - policy engine should NOT be consulted for Safe tier
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Should_NotQueryPolicyEngine_ForElevatedTier()
    {
        // Arrange
        var policy = new GraduatedCommandPolicy(
            _mockClassifier,
            _mockSecurityPolicy,
            _mockPolicyEngine,
            null,
            _defaultOptions);

        var request = new CommandExecutionRequest(
            "git",
            ["push", "origin", "main"],
            "/test",
            "Elevated tier - no policy engine query");

        _mockClassifier.Classify(request).Returns(CommandRiskTier.Elevated);

        // Act
        await policy.EvaluateAsync(request, CancellationToken.None);

        // Assert - policy engine should NOT be consulted for Elevated tier
        await _mockPolicyEngine.DidNotReceive().EvaluateAsync(
            Arg.Any<DirectoryAccessRequest>(),
            Arg.Any<CancellationToken>());
    }

    #endregion
}
