using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Tests for v0.3.0 graduated command execution with ICommandPolicy integration.
/// These tests verify that RunCommandTool correctly uses the command policy for tiered approval decisions.
/// </summary>
public sealed class GraduatedCommandExecutionTests : IDisposable
{
    private readonly string _testRoot;
    private readonly ISecurityPolicy _securityPolicy;
    private readonly ICommandPolicy _commandPolicy;
    private readonly RunCommandTool _tool;

    public GraduatedCommandExecutionTests()
    {
        // Use CI-safe test directory
        _testRoot = TestDirectoryHelper.GetTestDirectory("graduated-cmd-test");
        Directory.CreateDirectory(_testRoot);
        var fileOps = new SafeFileOperations(null);
        _securityPolicy = new CommandPolicy(fileOps);
        
        // Create command policy with classifier for graduated approval
        var classifier = new CommandRiskClassifier();
        var commandPolicyOptions = new CommandPolicyOptions
        {
            ModerateAutoApproveInTrustedDirs = true,
            TierOverrides = Array.Empty<CommandRiskRule>()
        };
        _commandPolicy = new GraduatedCommandPolicy(classifier, _securityPolicy, null, commandPolicyOptions);
        
        _tool = new RunCommandTool(_testRoot, _securityPolicy, commandTimeoutSeconds: 30, policyEngine: null, commandPolicy: _commandPolicy);
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    #region Safe Tier Tests (Auto-Approve)

    [Fact]
    public async Task SafeCommand_GitStatus_ShouldExecuteWithoutApproval()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "git", arguments = new[] { "status" } });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().NotStartWith("Error:");
        result.Should().Contain("Exit code:");
    }

    [Fact]
    public async Task SafeCommand_DotnetVersion_ShouldExecuteWithoutApproval()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "dotnet", arguments = new[] { "--version" } });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().NotStartWith("Error:");
        result.Should().Contain("Exit code: 0");
    }

    [Fact]
    public async Task SafeCommand_GitLog_ShouldExecuteWithoutApproval()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "git", arguments = new[] { "log", "--oneline", "-n", "5" } });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().NotStartWith("Error:");
        result.Should().Contain("Exit code:");
    }

    [Fact]
    public async Task SafeCommand_ReadOnlyCommands_ShouldExecuteWithoutApproval()
    {
        // Arrange - test various read-only commands
        var commands = new[]
        {
            new { executable = "echo", arguments = new[] { "test" } },
            new { executable = "cat", arguments = new[] { "README.md" } },  // Will fail if file doesn't exist, but should not require approval
        };

        foreach (var cmd in commands)
        {
            var input = JsonSerializer.SerializeToElement(cmd);

            // Act
            var result = await _tool.ExecuteAsync(input, CancellationToken.None);

            // Assert - Should execute (may fail due to missing file, but shouldn't throw approval exception)
            result.Should().NotBeNull();
            // Either succeeds or fails with execution error, but never throws CommandApprovalRequiredException
        }
    }

    #endregion

    #region Moderate Tier Tests (Context-Dependent)

    [Fact]
    public async Task ModerateCommand_WithoutPolicyEngine_ShouldRequireApproval()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "git", arguments = new[] { "add", "." } });

        // Act
        var act = async () => await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<CommandApprovalRequiredException>()
            .Where(ex => ex.Decision.Tier == CommandRiskTier.Moderate)
            .Where(ex => ex.Decision.RequiresApproval);
    }

    [Fact]
    public async Task ModerateCommand_DotnetBuild_ShouldRequireApproval()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "dotnet", arguments = new[] { "build" } });

        // Act
        var act = async () => await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<CommandApprovalRequiredException>()
            .Where(ex => ex.Decision.Tier == CommandRiskTier.Moderate)
            .Where(ex => ex.Request.Executable == "dotnet")
            .Where(ex => ex.Request.Arguments.Contains("build"));
    }

    [Fact]
    public async Task ModerateCommand_NpmRun_ShouldRequireApproval()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "npm", arguments = new[] { "run", "test" } });

        // Act
        var act = async () => await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<CommandApprovalRequiredException>()
            .Where(ex => ex.Decision.Tier == CommandRiskTier.Moderate);
    }

    #endregion

    #region Elevated Tier Tests (Always Require Approval)

    [Fact]
    public async Task ElevatedCommand_GitPush_ShouldRequireApproval()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "git", arguments = new[] { "push" } });

        // Act
        var act = async () => await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<CommandApprovalRequiredException>()
            .Where(ex => ex.Decision.Tier == CommandRiskTier.Elevated)
            .Where(ex => ex.Decision.RequiresApproval)
            .Where(ex => ex.Request.Executable == "git")
            .Where(ex => ex.Request.Arguments.Contains("push"));
    }

    [Fact]
    public async Task ElevatedCommand_NpmInstall_ShouldRequireApproval()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "npm", arguments = new[] { "install", "lodash" } });

        // Act
        var act = async () => await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<CommandApprovalRequiredException>()
            .Where(ex => ex.Decision.Tier == CommandRiskTier.Elevated)
            .Where(ex => ex.Request.Executable == "npm")
            .Where(ex => ex.Request.Arguments.Contains("install"));
    }

    [Fact]
    public async Task ElevatedCommand_DotnetPublish_ShouldRequireApproval()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "dotnet", arguments = new[] { "publish" } });

        // Act
        var act = async () => await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<CommandApprovalRequiredException>()
            .Where(ex => ex.Decision.Tier == CommandRiskTier.Elevated);
    }

    #endregion

    #region Dangerous Tier Tests (Always Blocked)

    [Theory]
    [InlineData("powershell")]
    [InlineData("curl")]
    [InlineData("wget")]
    [InlineData("cmd")]
    public async Task DangerousCommand_Blocklisted_ShouldReturnError(string executable)
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("validation failed");
    }

    [Fact]
    public async Task DangerousCommand_UnknownExecutable_ShouldReturnError()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "unknown-malicious-tool" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("not in the allowlist");
    }

    #endregion

    #region Exception Property Tests

    [Fact]
    public async Task CommandApprovalRequiredException_ShouldContainRequestDetails()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "git", arguments = new[] { "push", "origin", "main" } });

        // Act
        var exception = await Assert.ThrowsAsync<CommandApprovalRequiredException>(
            async () => await _tool.ExecuteAsync(input, CancellationToken.None));

        // Assert
        exception.Request.Should().NotBeNull();
        exception.Request.Executable.Should().Be("git");
        exception.Request.Arguments.Should().Contain("push");
        exception.Request.Arguments.Should().Contain("origin");
        exception.Request.Arguments.Should().Contain("main");
    }

    [Fact]
    public async Task CommandApprovalRequiredException_ShouldContainDecisionDetails()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "npm", arguments = new[] { "install" } });

        // Act
        var exception = await Assert.ThrowsAsync<CommandApprovalRequiredException>(
            async () => await _tool.ExecuteAsync(input, CancellationToken.None));

        // Assert
        exception.Decision.Should().NotBeNull();
        exception.Decision.Tier.Should().Be(CommandRiskTier.Elevated);
        exception.Decision.RequiresApproval.Should().BeTrue();
        exception.Decision.Reason.Should().NotBeNullOrWhiteSpace();
    }

    #endregion
}
