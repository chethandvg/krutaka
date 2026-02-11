using FluentAssertions;
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
        var handler = new ApprovalHandler(Environment.CurrentDirectory);
        var input = "{}";

        // Act & Assert
        var act = () => handler.RequestApproval(null!, input);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void RequestApproval_WithEmptyToolName_ThrowsArgumentException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory);
        var input = "{}";

        // Act & Assert
        var act = () => handler.RequestApproval("", input);
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void RequestApproval_WithWhitespaceToolName_ThrowsArgumentException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory);
        var input = "{}";

        // Act & Assert
        var act = () => handler.RequestApproval("   ", input);
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void RequestApproval_WithNullInput_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory);

        // Act & Assert
        var act = () => handler.RequestApproval("write_file", null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void RequestApproval_WithEmptyInput_ThrowsArgumentException()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory);

        // Act & Assert
        var act = () => handler.RequestApproval("write_file", "");
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void RequestApproval_WithInvalidJson_ReturnsDenied()
    {
        // Arrange
        var handler = new ApprovalHandler(Environment.CurrentDirectory);
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

    // Note: Interactive tests that require user input are not included here.
    // The approval handler's interactive functionality will be tested through
    // integration tests or manual verification.
}
