using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using NSubstitute;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Verifies that all tools correctly propagate DirectoryAccessRequiredException
/// to the AgentOrchestrator instead of swallowing it in their catch-all handlers.
/// </summary>
public sealed class DirectoryAccessExceptionPropagationTests : IDisposable
{
    private readonly string _testRoot;
    private readonly IAccessPolicyEngine _mockPolicyEngine;
    private readonly IFileOperations _fileOps;

    public DirectoryAccessExceptionPropagationTests()
    {
        _testRoot = TestDirectoryHelper.GetTestDirectory("dir-access-propagation");
        Directory.CreateDirectory(_testRoot);
        _fileOps = new SafeFileOperations(null);

        // Mock policy engine that returns RequiresApproval for any request
        _mockPolicyEngine = Substitute.For<IAccessPolicyEngine>();
        _mockPolicyEngine
            .EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var request = callInfo.Arg<DirectoryAccessRequest>();
                return AccessDecision.RequireApproval(request.Path);
            });
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task ListFilesTool_Should_PropagateDirectoryAccessRequiredException()
    {
        // Arrange
        var tool = new ListFilesTool(_testRoot, _fileOps, _mockPolicyEngine);
        var input = JsonSerializer.SerializeToElement(new { });

        // Act & Assert — exception must NOT be swallowed by catch-all
        var act = async () => await tool.ExecuteAsync(input, CancellationToken.None);
        await act.Should().ThrowAsync<DirectoryAccessRequiredException>();
    }

    [Fact]
    public async Task ReadFileTool_Should_PropagateDirectoryAccessRequiredException()
    {
        // Arrange
        var tool = new ReadFileTool(_testRoot, _fileOps, _mockPolicyEngine);
        var input = JsonSerializer.SerializeToElement(new { path = "test.txt" });

        // Act & Assert
        var act = async () => await tool.ExecuteAsync(input, CancellationToken.None);
        await act.Should().ThrowAsync<DirectoryAccessRequiredException>();
    }

    [Fact]
    public async Task SearchFilesTool_Should_PropagateDirectoryAccessRequiredException()
    {
        // Arrange
        var tool = new SearchFilesTool(_testRoot, _fileOps, _mockPolicyEngine);
        var input = JsonSerializer.SerializeToElement(new { pattern = "test" });

        // Act & Assert
        var act = async () => await tool.ExecuteAsync(input, CancellationToken.None);
        await act.Should().ThrowAsync<DirectoryAccessRequiredException>();
    }

    [Fact]
    public async Task WriteFileTool_Should_PropagateDirectoryAccessRequiredException()
    {
        // Arrange
        var tool = new WriteFileTool(_testRoot, _fileOps, _mockPolicyEngine);
        var input = JsonSerializer.SerializeToElement(new { path = "test.txt", content = "hello" });

        // Act & Assert
        var act = async () => await tool.ExecuteAsync(input, CancellationToken.None);
        await act.Should().ThrowAsync<DirectoryAccessRequiredException>();
    }

    [Fact]
    public async Task EditFileTool_Should_PropagateDirectoryAccessRequiredException()
    {
        // Arrange
        var tool = new EditFileTool(_testRoot, _fileOps, _mockPolicyEngine);
        var input = JsonSerializer.SerializeToElement(new { path = "test.txt", content = "hello", start_line = 1, end_line = 1 });

        // Act & Assert
        var act = async () => await tool.ExecuteAsync(input, CancellationToken.None);
        await act.Should().ThrowAsync<DirectoryAccessRequiredException>();
    }

    [Fact]
    public async Task RunCommandTool_Should_PropagateDirectoryAccessRequiredException()
    {
        // Arrange
        var mockSecurityPolicy = Substitute.For<ISecurityPolicy>();
        var tool = new RunCommandTool(_testRoot, mockSecurityPolicy, policyEngine: _mockPolicyEngine);
        // Provide a working_directory to trigger the policy engine evaluation
        var input = JsonSerializer.SerializeToElement(new { executable = "git", arguments = new[] { "status" }, working_directory = _testRoot });

        // Act & Assert
        var act = async () => await tool.ExecuteAsync(input, CancellationToken.None);
        await act.Should().ThrowAsync<DirectoryAccessRequiredException>();
    }
}
