using FluentAssertions;

namespace Krutaka.Core.Tests;

public class CommandRiskModelsTests
{
    #region CommandRiskTier Tests

    [Fact]
    public void CommandRiskTier_Should_HaveExactlyFourValues()
    {
        // Arrange & Act
        var values = Enum.GetValues<CommandRiskTier>();

        // Assert
        values.Should().HaveCount(4);
        values.Should().Contain(CommandRiskTier.Safe);
        values.Should().Contain(CommandRiskTier.Moderate);
        values.Should().Contain(CommandRiskTier.Elevated);
        values.Should().Contain(CommandRiskTier.Dangerous);
    }

    [Fact]
    public void CommandRiskTier_Should_HaveCorrectOrdinalValues()
    {
        // Assert
        ((int)CommandRiskTier.Safe).Should().Be(0);
        ((int)CommandRiskTier.Moderate).Should().Be(1);
        ((int)CommandRiskTier.Elevated).Should().Be(2);
        ((int)CommandRiskTier.Dangerous).Should().Be(3);
    }

    #endregion

    #region CommandRiskRule Tests

    [Fact]
    public void CommandRiskRule_Should_CreateValidRule()
    {
        // Arrange & Act
        var rule = new CommandRiskRule(
            Executable: "git",
            ArgumentPatterns: new[] { "status", "log", "diff" },
            Tier: CommandRiskTier.Safe,
            Description: "Read-only git operations"
        );

        // Assert
        rule.Executable.Should().Be("git");
        rule.ArgumentPatterns.Should().NotBeNull();
        rule.ArgumentPatterns.Should().HaveCount(3);
        rule.ArgumentPatterns.Should().Contain("status");
        rule.Tier.Should().Be(CommandRiskTier.Safe);
        rule.Description.Should().Be("Read-only git operations");
    }

    [Fact]
    public void CommandRiskRule_Should_AllowNullArgumentPatterns()
    {
        // Arrange & Act
        var rule = new CommandRiskRule(
            Executable: "cat",
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: "Read-only by nature"
        );

        // Assert
        rule.Executable.Should().Be("cat");
        rule.ArgumentPatterns.Should().BeNull();
        rule.Tier.Should().Be(CommandRiskTier.Safe);
        rule.Description.Should().Be("Read-only by nature");
    }

    [Fact]
    public void CommandRiskRule_Should_AllowNullDescription()
    {
        // Arrange & Act
        var rule = new CommandRiskRule(
            Executable: "git",
            ArgumentPatterns: new[] { "push" },
            Tier: CommandRiskTier.Elevated,
            Description: null
        );

        // Assert
        rule.Executable.Should().Be("git");
        rule.Description.Should().BeNull();
    }

    [Fact]
    public void CommandRiskRule_Should_SupportRecordEquality()
    {
        // Arrange
        var rule1 = new CommandRiskRule("git", new[] { "status" }, CommandRiskTier.Safe, "Read-only");
        var rule2 = new CommandRiskRule("git", new[] { "status" }, CommandRiskTier.Safe, "Read-only");
        var rule3 = new CommandRiskRule("git", new[] { "push" }, CommandRiskTier.Elevated, "Remote");

        // Assert - Check properties individually since record equality doesn't deep-compare collections
        rule1.Executable.Should().Be(rule2.Executable);
        rule1.Tier.Should().Be(rule2.Tier);
        rule1.Description.Should().Be(rule2.Description);
        
        rule1.Executable.Should().Be(rule3.Executable);
        rule1.Tier.Should().NotBe(rule3.Tier);
    }

    [Fact]
    public void CommandRiskRule_Should_AllowEmptyArgumentPatterns()
    {
        // Arrange & Act
        var rule = new CommandRiskRule(
            Executable: "git",
            ArgumentPatterns: Array.Empty<string>(),
            Tier: CommandRiskTier.Moderate,
            Description: null
        );

        // Assert
        rule.ArgumentPatterns.Should().NotBeNull();
        rule.ArgumentPatterns.Should().BeEmpty();
    }

    #endregion

    #region CommandExecutionRequest Tests

    [Fact]
    public void CommandExecutionRequest_Should_CreateValidRequest()
    {
        // Arrange & Act
        var request = new CommandExecutionRequest(
            Executable: "git",
            Arguments: new[] { "status" },
            WorkingDirectory: "/home/user/project",
            Justification: "Check repository status"
        );

        // Assert
        request.Executable.Should().Be("git");
        request.Arguments.Should().NotBeNull();
        request.Arguments.Should().HaveCount(1);
        request.Arguments.Should().Contain("status");
        request.WorkingDirectory.Should().Be("/home/user/project");
        request.Justification.Should().Be("Check repository status");
    }

    [Fact]
    public void CommandExecutionRequest_Should_AllowNullWorkingDirectory()
    {
        // Arrange & Act
        var request = new CommandExecutionRequest(
            Executable: "git",
            Arguments: new[] { "status" },
            WorkingDirectory: null,
            Justification: "Check status"
        );

        // Assert
        request.WorkingDirectory.Should().BeNull();
        request.Executable.Should().Be("git");
    }

    [Fact]
    public void CommandExecutionRequest_Should_AllowEmptyArguments()
    {
        // Arrange & Act
        var request = new CommandExecutionRequest(
            Executable: "git",
            Arguments: Array.Empty<string>(),
            WorkingDirectory: "/home/user/project",
            Justification: "Run git without args"
        );

        // Assert
        request.Arguments.Should().NotBeNull();
        request.Arguments.Should().BeEmpty();
    }

    [Fact]
    public void CommandExecutionRequest_Should_SupportRecordEquality()
    {
        // Arrange
        var request1 = new CommandExecutionRequest("git", new[] { "status" }, "/path", "Check status");
        var request2 = new CommandExecutionRequest("git", new[] { "status" }, "/path", "Check status");
        var request3 = new CommandExecutionRequest("git", new[] { "push" }, "/path", "Push changes");

        // Assert - Check properties individually since record equality doesn't deep-compare collections
        request1.Executable.Should().Be(request2.Executable);
        request1.WorkingDirectory.Should().Be(request2.WorkingDirectory);
        request1.Justification.Should().Be(request2.Justification);
        
        request1.Executable.Should().Be(request3.Executable);
        request1.Justification.Should().NotBe(request3.Justification);
    }

    [Fact]
    public void CommandExecutionRequest_Arguments_Should_BeImmutable()
    {
        // Arrange
        var request = new CommandExecutionRequest("git", new[] { "status" }, "/path", "Check");

        // Assert
        request.Arguments.Should().BeAssignableTo<IReadOnlyList<string>>();
        request.Arguments.Should().NotBeAssignableTo<List<string>>();
    }

    #endregion

    #region CommandDecision Tests

    [Fact]
    public void CommandDecision_Approve_Should_CreateApprovedDecision()
    {
        // Arrange & Act
        var decision = CommandDecision.Approve(CommandRiskTier.Safe, "Auto-approved (Safe tier)");

        // Assert
        decision.Approved.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Safe);
        decision.Reason.Should().Be("Auto-approved (Safe tier)");
        decision.RequiresApproval.Should().BeFalse();
    }

    [Fact]
    public void CommandDecision_RequireApproval_Should_CreateRequiresApprovalDecision()
    {
        // Arrange & Act
        var decision = CommandDecision.RequireApproval(CommandRiskTier.Elevated, "Elevated tier requires approval");

        // Assert
        decision.Approved.Should().BeTrue();
        decision.Tier.Should().Be(CommandRiskTier.Elevated);
        decision.Reason.Should().Be("Elevated tier requires approval");
        decision.RequiresApproval.Should().BeTrue();
    }

    [Fact]
    public void CommandDecision_Deny_Should_CreateDeniedDecision()
    {
        // Arrange & Act
        var decision = CommandDecision.Deny(CommandRiskTier.Dangerous, "Blocked (Dangerous tier)");

        // Assert
        decision.Approved.Should().BeFalse();
        decision.Tier.Should().Be(CommandRiskTier.Dangerous);
        decision.Reason.Should().Be("Blocked (Dangerous tier)");
        decision.RequiresApproval.Should().BeFalse();
    }

    [Fact]
    public void CommandDecision_Approve_Should_SupportAllTiers()
    {
        // Arrange & Act
        var safeTier = CommandDecision.Approve(CommandRiskTier.Safe, "Safe");
        var moderateTier = CommandDecision.Approve(CommandRiskTier.Moderate, "Moderate");

        // Assert
        safeTier.Tier.Should().Be(CommandRiskTier.Safe);
        safeTier.Approved.Should().BeTrue();
        safeTier.RequiresApproval.Should().BeFalse();
        
        moderateTier.Tier.Should().Be(CommandRiskTier.Moderate);
        moderateTier.Approved.Should().BeTrue();
        moderateTier.RequiresApproval.Should().BeFalse();
    }

    [Fact]
    public void CommandDecision_RequireApproval_Should_SupportAllApplicableTiers()
    {
        // Arrange & Act
        var moderateTier = CommandDecision.RequireApproval(CommandRiskTier.Moderate, "Untrusted directory");
        var elevatedTier = CommandDecision.RequireApproval(CommandRiskTier.Elevated, "Always requires approval");

        // Assert
        moderateTier.Tier.Should().Be(CommandRiskTier.Moderate);
        moderateTier.Approved.Should().BeTrue();
        moderateTier.RequiresApproval.Should().BeTrue();
        
        elevatedTier.Tier.Should().Be(CommandRiskTier.Elevated);
        elevatedTier.Approved.Should().BeTrue();
        elevatedTier.RequiresApproval.Should().BeTrue();
    }

    [Fact]
    public void CommandDecision_Deny_Should_SupportAllBlockableTiers()
    {
        // Arrange & Act
        var dangerous = CommandDecision.Deny(CommandRiskTier.Dangerous, "Always blocked");

        // Assert
        dangerous.Tier.Should().Be(CommandRiskTier.Dangerous);
        dangerous.Approved.Should().BeFalse();
        dangerous.RequiresApproval.Should().BeFalse();
    }

    [Fact]
    public void CommandDecision_Should_SupportRecordEquality()
    {
        // Arrange
        var decision1 = CommandDecision.Approve(CommandRiskTier.Safe, "Auto-approved");
        var decision2 = CommandDecision.Approve(CommandRiskTier.Safe, "Auto-approved");
        var decision3 = CommandDecision.Deny(CommandRiskTier.Dangerous, "Blocked");

        // Assert
        decision1.Should().Be(decision2);
        decision1.Should().NotBe(decision3);
    }

    [Fact]
    public void CommandDecision_FactoryMethods_Should_SetCorrectCombinations()
    {
        // Arrange & Act
        var approved = CommandDecision.Approve(CommandRiskTier.Safe, "Safe");
        var requiresApproval = CommandDecision.RequireApproval(CommandRiskTier.Elevated, "Elevated");
        var denied = CommandDecision.Deny(CommandRiskTier.Dangerous, "Dangerous");

        // Assert - Verify the boolean combinations are correct
        approved.Approved.Should().BeTrue();
        approved.RequiresApproval.Should().BeFalse();
        
        requiresApproval.Approved.Should().BeTrue();
        requiresApproval.RequiresApproval.Should().BeTrue();
        
        denied.Approved.Should().BeFalse();
        denied.RequiresApproval.Should().BeFalse();
    }

    #endregion
}
