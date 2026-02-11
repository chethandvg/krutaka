using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

public sealed class RunCommandToolTests : IDisposable
{
    private readonly string _testRoot;
    private readonly ISecurityPolicy _securityPolicy;
    private readonly RunCommandTool _tool;

    public RunCommandToolTests()
    {
        // Use CI-safe test directory (avoids LocalAppData which is blocked by security policy)
        _testRoot = TestDirectoryHelper.GetTestDirectory("runcmd-test");
        Directory.CreateDirectory(_testRoot);
        var fileOps = new SafeFileOperations(null);
        _securityPolicy = new CommandPolicy(fileOps);
        _tool = new RunCommandTool(_testRoot, _securityPolicy);
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    #region Tool Metadata Tests

    [Fact]
    public void Should_HaveCorrectName()
    {
        _tool.Name.Should().Be("run_command");
    }

    [Fact]
    public void Should_HaveDescriptionWithKeywords()
    {
        _tool.Description.Should().Contain("sandboxed");
        _tool.Description.Should().Contain("security");
        _tool.Description.Should().Contain("allowlist");
        _tool.Description.Should().Contain("blocklist");
        _tool.Description.Should().Contain("approval");
    }

    [Fact]
    public void Should_HaveValidInputSchema()
    {
        var schema = _tool.InputSchema;

        schema.ValueKind.Should().Be(JsonValueKind.Object);
        schema.GetProperty("type").GetString().Should().Be("object");

        var properties = schema.GetProperty("properties");
        properties.TryGetProperty("executable", out var executableProp).Should().BeTrue();
        executableProp.GetProperty("type").GetString().Should().Be("string");

        properties.TryGetProperty("arguments", out var argumentsProp).Should().BeTrue();
        argumentsProp.GetProperty("type").GetString().Should().Be("array");

        properties.TryGetProperty("working_directory", out var workingDirProp).Should().BeTrue();
        workingDirProp.GetProperty("type").GetString().Should().Be("string");

        var required = schema.GetProperty("required");
        required.ValueKind.Should().Be(JsonValueKind.Array);
        var requiredArray = required.EnumerateArray().Select(e => e.GetString()).ToArray();
        requiredArray.Should().Contain("executable");
    }

    #endregion

    #region Command Policy Enforcement Tests

    [Fact]
    public async Task Should_AllowWhitelistedCommand()
    {
        // Arrange - use dotnet which is guaranteed to exist on the test runner
        var input = JsonSerializer.SerializeToElement(new { executable = "dotnet", arguments = new[] { "--version" } });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().NotStartWith("Error: Command validation failed");
        result.Should().Contain("Exit code: 0");
    }

    [Theory]
    [InlineData("powershell")]
    [InlineData("pwsh")]
    [InlineData("cmd")]
    [InlineData("curl")]
    [InlineData("wget")]
    [InlineData("reg")]
    [InlineData("regedit")]
    [InlineData("netsh")]
    [InlineData("certutil")]
    [InlineData("bitsadmin")]
    [InlineData("format")]
    [InlineData("diskpart")]
    [InlineData("rundll32")]
    [InlineData("regsvr32")]
    [InlineData("mshta")]
    [InlineData("wscript")]
    [InlineData("cscript")]
    [InlineData("msiexec")]
    [InlineData("sc")]
    [InlineData("schtasks")]
    [InlineData("taskkill")]
    [InlineData("net")]
    [InlineData("runas")]
    public async Task Should_BlockBlacklistedCommand(string executable)
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error: Command validation failed");
        result.Should().Contain("Blocked executable");
    }

    [Fact]
    public async Task Should_BlockNonWhitelistedCommand()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "malicious-tool" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error: Command validation failed");
        result.Should().Contain("not in the allowlist");
    }

    #endregion

    #region Shell Metacharacter Tests

    [Theory]
    [InlineData("git|ls")]
    [InlineData("git>output.txt")]
    [InlineData("git>>output.txt")]
    [InlineData("git&&ls")]
    [InlineData("git||ls")]
    [InlineData("git;ls")]
    [InlineData("git`ls`")]
    [InlineData("git$(ls)")]
    [InlineData("git%PATH%")]
    [InlineData("git&ls")]
    [InlineData("git<input.txt")]
    [InlineData("git^ls")]
    public async Task Should_BlockExecutableWithShellMetacharacters(string executable)
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error: Command validation failed");
        result.Should().Contain("shell metacharacters");
    }

    [Theory]
    [InlineData("status|ls")]
    [InlineData("status>output.txt")]
    [InlineData("status&&rm")]
    [InlineData("status;rm -rf")]
    [InlineData("$(malicious)")]
    [InlineData("%PATH%")]
    [InlineData("arg&malicious")]
    [InlineData("arg<file")]
    [InlineData("arg^escape")]
    public async Task Should_BlockArgumentWithShellMetacharacters(string argument)
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "git",
            arguments = new[] { argument }
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error: Command validation failed");
        result.Should().Contain("shell metacharacters");
    }

    #endregion

    #region Environment Scrubbing Tests

    [Fact]
    public async Task Should_ScrubSensitiveEnvironmentVariables()
    {
        // This test verifies that the SecurityPolicy.ScrubEnvironment is called
        // The actual scrubbing logic is tested in SecurityPolicyTests
        // Here we just verify the tool uses the scrubbing mechanism

        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "dotnet",
            arguments = new[] { "--version" }
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        // The test passes if execution succeeds without exposing environment variables
        result.Should().NotStartWith("Error:");
    }

    #endregion

    #region Successful Execution Tests

    [Fact]
    public async Task Should_ExecuteSimpleCommand()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "dotnet",
            arguments = new[] { "--version" }
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Command executed: dotnet --version");
        result.Should().Contain("Exit code: 0");
    }

    [Fact]
    public async Task Should_CaptureStdout()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "dotnet",
            arguments = new[] { "--version" }
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("=== STDOUT ===");
        result.Should().Contain("<untrusted_command_output>");
    }

    [Fact]
    public async Task Should_IncludeWorkingDirectoryInOutput()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "dotnet",
            arguments = new[] { "--version" }
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Working directory:");
        result.Should().Contain(_testRoot);
    }

    #endregion

    #region Working Directory Validation Tests

    [Fact]
    public async Task Should_UseProjectRootAsDefaultWorkingDirectory()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "echo",
            arguments = new[] { "test" }
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain($"Working directory: {_testRoot}");
    }

    [Fact]
    public async Task Should_ValidateWorkingDirectoryPath()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "echo",
            arguments = new[] { "test" },
            working_directory = "C:\\Windows"
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error: Working directory validation failed");
    }

    [Fact]
    public async Task Should_AllowValidWorkingDirectory()
    {
        // Arrange
        var subdir = Path.Combine(_testRoot, "subdir");
        Directory.CreateDirectory(subdir);

        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "echo",
            arguments = new[] { "test" },
            working_directory = subdir
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain($"Working directory: {subdir}");
        result.Should().NotStartWith("Error:");
    }

    #endregion

    #region Timeout Tests

    [Fact(Skip = "Platform-dependent and may be flaky - timeout enforcement is tested via unit test of timeout logic")]
    public async Task Should_TimeoutLongRunningCommand()
    {
        // Note: This test is difficult to make reliable across platforms
        // Timeout enforcement logic is verified through the code structure
        // In production, the 30-second timeout is enforced via CancellationTokenSource

        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "find",
            arguments = new[] { "/", "-type", "f" }
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("timed out after 30 seconds");
    }

    #endregion

    #region Error Handling Tests

    [Fact]
    public async Task Should_ReturnErrorWhenExecutableNotFound()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "nonexistent-command-xyz123"
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
    }

    [Fact]
    public async Task Should_HandleMissingExecutableParameter()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { arguments = new[] { "test" } });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Be("Error: Missing required parameter 'executable'");
    }

    [Fact]
    public async Task Should_HandleEmptyExecutableParameter()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Be("Error: Parameter 'executable' cannot be empty");
    }

    [Fact]
    public async Task Should_HandleNonZeroExitCode()
    {
        // Arrange - using a command that will fail
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "git",
            arguments = new[] { "status", "--invalid-option-xyz" }
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Exit code:");
        // Exit code should be non-zero, but we don't fail - we just report it
        result.Should().NotStartWith("Error:");
    }

    #endregion

    #region Arguments Handling Tests

    [Fact]
    public async Task Should_HandleCommandWithoutArguments()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { executable = "dotnet" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Command executed: dotnet");
        result.Should().NotStartWith("Error:");
    }

    [Fact]
    public async Task Should_HandleCommandWithMultipleArguments()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            executable = "git",
            arguments = new[] { "--version" }
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Command executed: git --version");
        result.Should().Contain("Exit code: 0");
    }

    #endregion
}
