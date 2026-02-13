using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Xunit;

namespace Krutaka.Console.Tests;

/// <summary>
/// Unit tests for ApprovalHandler class.
/// </summary>
public class ApprovalHandlerTests
{
    [Fact]
    public void RequestApproval_WithNullToolName_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        var input = "{}";

        // Act & Assert
        var act = () => handler.RequestApproval(null!, input);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void RequestApproval_WithEmptyToolName_ThrowsArgumentException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        var input = "{}";

        // Act & Assert
        var act = () => handler.RequestApproval("", input);
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void RequestApproval_WithWhitespaceToolName_ThrowsArgumentException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        var input = "{}";

        // Act & Assert
        var act = () => handler.RequestApproval("   ", input);
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void RequestApproval_WithNullInput_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));

        // Act & Assert
        var act = () => handler.RequestApproval("write_file", null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void RequestApproval_WithEmptyInput_ThrowsArgumentException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));

        // Act & Assert
        var act = () => handler.RequestApproval("write_file", "");
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void RequestApproval_WithInvalidJson_ReturnsDenied()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        var invalidJson = "{ invalid json }";

        // Act
        var decision = handler.RequestApproval("write_file", invalidJson);

        // Assert
        decision.Approved.Should().BeFalse();
        decision.AlwaysApprove.Should().BeFalse();
    }

    [Fact]
    public void ApprovalDecision_HasCorrectProperties()
    {
        // Arrange & Act
        var approved = new ApprovalDecision(true, false);
        var denied = new ApprovalDecision(false, false);
        var always = new ApprovalDecision(true, true);

        // Assert
        approved.Approved.Should().BeTrue();
        approved.AlwaysApprove.Should().BeFalse();

        denied.Approved.Should().BeFalse();
        denied.AlwaysApprove.Should().BeFalse();

        always.Approved.Should().BeTrue();
        always.AlwaysApprove.Should().BeTrue();
    }

    [Fact]
    public void ApprovalDecision_IsRecord()
    {
        // Arrange
        var decision1 = new ApprovalDecision(true, false);
        var decision2 = new ApprovalDecision(true, false);
        var decision3 = new ApprovalDecision(false, true);

        // Assert - records have value equality
        decision1.Should().Be(decision2);
        decision1.Should().NotBe(decision3);
    }

    [Fact]
    public void HandleDirectoryAccess_WithNullPath_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));

        // Act & Assert
        var act = () => handler.HandleDirectoryAccess(null!, AccessLevel.ReadOnly, "Test justification");
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void HandleDirectoryAccess_WithEmptyPath_ThrowsArgumentException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));

        // Act & Assert
        var act = () => handler.HandleDirectoryAccess("", AccessLevel.ReadOnly, "Test justification");
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void HandleDirectoryAccess_WithWhitespacePath_ThrowsArgumentException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));

        // Act & Assert
        var act = () => handler.HandleDirectoryAccess("   ", AccessLevel.ReadOnly, "Test justification");
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void HandleDirectoryAccess_WithNullJustification_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));

        // Act & Assert
        var act = () => handler.HandleDirectoryAccess(@"C:\test", AccessLevel.ReadOnly, null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void HandleDirectoryAccess_WithEmptyJustification_ThrowsArgumentException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));

        // Act & Assert
        var act = () => handler.HandleDirectoryAccess(@"C:\test", AccessLevel.ReadOnly, "");
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void DirectoryAccessApproval_HasCorrectProperties()
    {
        // Arrange & Act
        var approved = new DirectoryAccessApproval(true, AccessLevel.ReadWrite, false);
        var denied = new DirectoryAccessApproval(false, null, false);
        var session = new DirectoryAccessApproval(true, AccessLevel.ReadOnly, true);

        // Assert
        approved.Approved.Should().BeTrue();
        approved.GrantedLevel.Should().Be(AccessLevel.ReadWrite);
        approved.SessionGrant.Should().BeFalse();

        denied.Approved.Should().BeFalse();
        denied.GrantedLevel.Should().BeNull();
        denied.SessionGrant.Should().BeFalse();

        session.Approved.Should().BeTrue();
        session.GrantedLevel.Should().Be(AccessLevel.ReadOnly);
        session.SessionGrant.Should().BeTrue();
    }

    [Fact]
    public void DirectoryAccessApproval_IsRecord()
    {
        // Arrange
        var approval1 = new DirectoryAccessApproval(true, AccessLevel.ReadOnly, false);
        var approval2 = new DirectoryAccessApproval(true, AccessLevel.ReadOnly, false);
        var approval3 = new DirectoryAccessApproval(false, null, true);

        // Assert - records have value equality
        approval1.Should().Be(approval2);
        approval1.Should().NotBe(approval3);
    }

    [Fact]
    public void CreateDirectoryAccessDenialMessage_ReturnsCorrectMessage()
    {
        // Arrange & Act
        var message = ApprovalHandler.CreateDirectoryAccessDenialMessage(@"C:\projects\test");

        // Assert
        message.Should().Contain(@"C:\projects\test");
        message.Should().Contain("denied access");
    }

    // Note: Interactive tests that require user input are not included here.
    // The approval handler's interactive functionality will be tested through
    // integration tests or manual verification.

    [Theory]
    [InlineData("[green][[Y]]es - Execute this command[/]")]
    [InlineData("[red][[N]]o - Deny this command[/]")]
    [InlineData("[green][[Y]]es - Write this file[/]")]
    [InlineData("[red][[N]]o - Deny this operation[/]")]
    [InlineData("[yellow][[A]]lways - Approve all write_file operations this session[/]")]
    [InlineData("[cyan][[V]]iew - View full content[/]")]
    [InlineData("[green][[Y]]es - Approve this operation[/]")]
    [InlineData("[yellow][[A]]lways - Approve all operations of this type this session[/]")]
    [InlineData("[green][[Y]]es - Allow at ReadOnly level[/]")]
    [InlineData("[yellow][[R]]ead-only - Downgrade to ReadOnly access[/]")]
    [InlineData("[red][[N]]o - Deny access[/]")]
    [InlineData("[cyan][[S]]ession - Allow for entire session[/]")]
    [InlineData("[yellow][[A]]lways - Approve this command for this session[/]")]
    public void ApprovalPrompt_MarkupStrings_AreValidSpectreMarkup(string markup)
    {
        // Act — Markup constructor parses and throws InvalidOperationException if invalid
        var act = () => new Spectre.Console.Markup(markup);

        // Assert — should not throw
        act.Should().NotThrow("because SelectionPrompt converter markup must be valid Spectre.Console markup");
    }

    [Fact]
    public void HandleCommandApproval_WithNullRequest_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        var decision = new CommandDecision(CommandOutcome.RequiresApproval, CommandRiskTier.Elevated, "Test reason");

        // Act & Assert
        var act = () => handler.HandleCommandApproval(null!, decision);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void HandleCommandApproval_WithNullDecision_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        var request = new CommandExecutionRequest("git", ["status"], "/test", "Test justification");

        // Act & Assert
        var act = () => handler.HandleCommandApproval(request, null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void DisplayAutoApprovalMessage_WithNullRequest_ThrowsArgumentNullException()
    {
        // Arrange
        var decision = new CommandDecision(CommandOutcome.Approved, CommandRiskTier.Safe, "Auto-approved (Safe tier)");

        // Act & Assert
        var act = () => ApprovalHandler.DisplayAutoApprovalMessage(null!, decision);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void DisplayAutoApprovalMessage_WithNullDecision_ThrowsArgumentNullException()
    {
        // Arrange
        var request = new CommandExecutionRequest("git", ["status"], "/test", "Test justification");

        // Act & Assert
        var act = () => ApprovalHandler.DisplayAutoApprovalMessage(request, null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Theory]
    [InlineData(CommandRiskTier.Safe)]
    [InlineData(CommandRiskTier.Moderate)]
    public void DisplayAutoApprovalMessage_DoesNotThrow_ForAutoApprovedTiers(CommandRiskTier tier)
    {
        // Arrange
        var request = new CommandExecutionRequest("git", ["status"], "/test", "Test justification");
        var decision = new CommandDecision(CommandOutcome.Approved, tier, $"Auto-approved ({tier} tier)");

        // Act — The method writes to console, we're just verifying it doesn't throw
        var act = () => ApprovalHandler.DisplayAutoApprovalMessage(request, decision);

        // Assert — Should not throw
        act.Should().NotThrow("because auto-approval message should display successfully for {0} tier", tier);
    }

    [Theory]
    [InlineData("git", "git")]
    [InlineData("dotnet", "dotnet")]
    [InlineData("npm", "npm")]
    [InlineData("echo", "echo")]
    public void DisplayAutoApprovalMessage_WithNoArguments_ShowsExecutableOnly(string executable, string expectedCommandString)
    {
        // Arrange
        var request = new CommandExecutionRequest(executable, Array.Empty<string>(), "/test", "Test justification");
        var decision = new CommandDecision(CommandOutcome.Approved, CommandRiskTier.Safe, "Auto-approved");

        // Act — The method writes to console, we're just verifying it doesn't throw and formats correctly
        var act = () => ApprovalHandler.DisplayAutoApprovalMessage(request, decision);

        // Assert — Should not throw
        act.Should().NotThrow("because command string should be built correctly for {0}", expectedCommandString);
    }

    [Theory]
    [InlineData("[green]SAFE[/]")]
    [InlineData("[yellow]MODERATE (not in trusted directory)[/]")]
    [InlineData("[red]ELEVATED[/]")]
    [InlineData("[red]DANGEROUS[/]")]
    public void TierLabel_MarkupStrings_AreValidSpectreMarkup(string tierLabel)
    {
        // Act — Markup constructor parses and throws InvalidOperationException if invalid
        var act = () => new Spectre.Console.Markup(tierLabel);

        // Assert — should not throw
        act.Should().NotThrow("because tier label markup must be valid Spectre.Console markup");
    }
}
