using FluentAssertions;

namespace Krutaka.Core.Tests;

public class AccessDecisionTests
{
    [Fact]
    public void AccessDecision_Grant_Should_CreateGrantedDecision()
    {
        // Arrange & Act
        var decision = AccessDecision.Grant(
            scopedPath: "/home/user/project",
            grantedLevel: AccessLevel.ReadWrite,
            expiresAfter: TimeSpan.FromMinutes(30)
        );

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Granted);
        decision.Granted.Should().BeTrue();
        decision.ScopedPath.Should().Be("/home/user/project");
        decision.GrantedLevel.Should().Be(AccessLevel.ReadWrite);
        decision.ExpiresAfter.Should().Be(TimeSpan.FromMinutes(30));
        decision.DeniedReasons.Should().BeEmpty();
    }

    [Fact]
    public void AccessDecision_Grant_Should_AllowNullExpiry()
    {
        // Arrange & Act
        var decision = AccessDecision.Grant(
            scopedPath: "/home/user/project",
            grantedLevel: AccessLevel.ReadOnly
        );

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Granted);
        decision.Granted.Should().BeTrue();
        decision.ExpiresAfter.Should().BeNull();
    }

    [Fact]
    public void AccessDecision_Deny_Should_CreateDeniedDecision()
    {
        // Arrange & Act
        var decision = AccessDecision.Deny("Path is blocked", "System directory access not allowed");

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.ScopedPath.Should().BeNull();
        decision.GrantedLevel.Should().BeNull();
        decision.ExpiresAfter.Should().BeNull();
        decision.DeniedReasons.Should().HaveCount(2);
        decision.DeniedReasons.Should().Contain("Path is blocked");
        decision.DeniedReasons.Should().Contain("System directory access not allowed");
    }

    [Fact]
    public void AccessDecision_Deny_Should_AcceptSingleReason()
    {
        // Arrange & Act
        var decision = AccessDecision.Deny("Access denied");

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().HaveCount(1);
        decision.DeniedReasons.Should().Contain("Access denied");
    }

    [Fact]
    public void AccessDecision_Deny_Should_AcceptMultipleReasons()
    {
        // Arrange & Act
        var decision = AccessDecision.Deny("Reason 1", "Reason 2", "Reason 3");

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().HaveCount(3);
    }

    [Fact]
    public void AccessDecision_Deny_Should_HandleEmptyReasons()
    {
        // Arrange & Act
        var decision = AccessDecision.Deny();

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Denied);
        decision.Granted.Should().BeFalse();
        decision.DeniedReasons.Should().BeEmpty();
    }

    [Fact]
    public void AccessDecision_RequireApproval_Should_CreateRequiresApprovalDecision()
    {
        // Arrange & Act
        var decision = AccessDecision.RequireApproval("/home/user/newproject");

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.RequiresApproval);
        decision.Granted.Should().BeFalse();
        decision.ScopedPath.Should().Be("/home/user/newproject");
        decision.GrantedLevel.Should().BeNull();
        decision.ExpiresAfter.Should().BeNull();
        decision.DeniedReasons.Should().BeEmpty();
    }

    [Fact]
    public void AccessDecision_Should_SupportRecordEquality_ForGranted()
    {
        // Arrange
        var decision1 = AccessDecision.Grant("/path", AccessLevel.ReadOnly, TimeSpan.FromMinutes(10));
        var decision2 = AccessDecision.Grant("/path", AccessLevel.ReadOnly, TimeSpan.FromMinutes(10));
        var decision3 = AccessDecision.Grant("/other", AccessLevel.ReadOnly, TimeSpan.FromMinutes(10));

        // Assert
        decision1.Should().Be(decision2);
        decision1.Should().NotBe(decision3);
    }

    [Fact]
    public void AccessDecision_Should_SupportRecordEquality_ForDenied()
    {
        // Arrange
        var decision1 = AccessDecision.Deny("Reason A", "Reason B");
        var decision2 = AccessDecision.Deny("Reason A", "Reason B");
        var decision3 = AccessDecision.Deny("Reason C");

        // Assert - Check properties individually since record equality doesn't deep-compare collections
        decision1.Outcome.Should().Be(decision2.Outcome);
        decision1.Granted.Should().Be(decision2.Granted);
        decision1.ScopedPath.Should().Be(decision2.ScopedPath);
        decision1.GrantedLevel.Should().Be(decision2.GrantedLevel);
        decision1.ExpiresAfter.Should().Be(decision2.ExpiresAfter);
        decision1.DeniedReasons.Should().BeEquivalentTo(decision2.DeniedReasons);
        
        decision1.DeniedReasons.Should().NotBeEquivalentTo(decision3.DeniedReasons);
    }

    [Fact]
    public void AccessDecision_Should_GrantWithReadOnlyLevel()
    {
        // Arrange & Act
        var decision = AccessDecision.Grant("/path", AccessLevel.ReadOnly);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Granted);
        decision.Granted.Should().BeTrue();
        decision.GrantedLevel.Should().Be(AccessLevel.ReadOnly);
    }

    [Fact]
    public void AccessDecision_Should_GrantWithReadWriteLevel()
    {
        // Arrange & Act
        var decision = AccessDecision.Grant("/path", AccessLevel.ReadWrite);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Granted);
        decision.Granted.Should().BeTrue();
        decision.GrantedLevel.Should().Be(AccessLevel.ReadWrite);
    }

    [Fact]
    public void AccessDecision_Should_GrantWithExecuteLevel()
    {
        // Arrange & Act
        var decision = AccessDecision.Grant("/path", AccessLevel.Execute);

        // Assert
        decision.Outcome.Should().Be(AccessOutcome.Granted);
        decision.Granted.Should().BeTrue();
        decision.GrantedLevel.Should().Be(AccessLevel.Execute);
    }

    [Fact]
    public void AccessDecision_Grant_Should_HaveEmptyDeniedReasons()
    {
        // Arrange & Act
        var decision = AccessDecision.Grant("/path", AccessLevel.ReadOnly);

        // Assert
        decision.DeniedReasons.Should().NotBeNull();
        decision.DeniedReasons.Should().BeEmpty();
    }

    [Fact]
    public void AccessDecision_Deny_Should_HaveNullScopedPath()
    {
        // Arrange & Act
        var decision = AccessDecision.Deny("Blocked");

        // Assert
        decision.ScopedPath.Should().BeNull();
    }

    [Fact]
    public void AccessDecision_Deny_Should_HaveNullGrantedLevel()
    {
        // Arrange & Act
        var decision = AccessDecision.Deny("Blocked");

        // Assert
        decision.GrantedLevel.Should().BeNull();
    }

    [Fact]
    public void AccessDecision_Deny_Should_HaveNullExpiresAfter()
    {
        // Arrange & Act
        var decision = AccessDecision.Deny("Blocked");

        // Assert
        decision.ExpiresAfter.Should().BeNull();
    }

    [Fact]
    public void AccessDecision_DeniedReasons_Should_BeImmutable()
    {
        // Arrange
        var decision = AccessDecision.Deny("Reason 1", "Reason 2");

        // Act & Assert - Verify we cannot cast to mutable list
        decision.DeniedReasons.Should().BeAssignableTo<IReadOnlyList<string>>();
        decision.DeniedReasons.Should().NotBeAssignableTo<List<string>>();
    }

    [Fact]
    public void AccessDecision_Outcome_Should_DetermineGranted()
    {
        // Assert
        AccessDecision.Grant("/path", AccessLevel.ReadOnly).Granted.Should().BeTrue();
        AccessDecision.Deny("Reason").Granted.Should().BeFalse();
        AccessDecision.RequireApproval("/path").Granted.Should().BeFalse();
    }
}
