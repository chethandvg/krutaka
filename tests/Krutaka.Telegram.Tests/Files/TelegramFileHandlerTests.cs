using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Telegram.Bot;
using Telegram.Bot.Types;

#pragma warning disable CA2000 // Mock objects in tests do not need disposal  
#pragma warning disable CA1031 // Tests may catch general exceptions during cleanup

namespace Krutaka.Telegram.Tests;

public sealed class TelegramFileHandlerTests : IDisposable
{
    private readonly ITelegramBotClient _botClient;
    private readonly IAccessPolicyEngine _accessPolicyEngine;
    private readonly ILogger<TelegramFileHandler> _logger;
    private readonly TelegramFileHandler _handler;
    private readonly string _tempTestDir;
    private readonly string _projectPath;

    public TelegramFileHandlerTests()
    {
        _botClient = Substitute.For<ITelegramBotClient>();
        _accessPolicyEngine = Substitute.For<IAccessPolicyEngine>();
        _logger = Substitute.For<ILogger<TelegramFileHandler>>();
        _handler = new TelegramFileHandler(_botClient, _accessPolicyEngine, _logger);

        _tempTestDir = Path.Combine(Path.GetTempPath(), $"krutaka-filehandler-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempTestDir);

        _projectPath = Path.Combine(_tempTestDir, "project");
        Directory.CreateDirectory(_projectPath);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempTestDir))
        {
            try
            {
                Directory.Delete(_tempTestDir, recursive: true);
            }
            catch
            {
                // Ignore cleanup errors
            }
        }

        GC.SuppressFinalize(this);
    }

    private ManagedSession CreateMockSession()
    {
        var claudeClient = Substitute.For<IClaudeClient>();
        var toolRegistry = Substitute.For<IToolRegistry>();
        var securityPolicy = Substitute.For<ISecurityPolicy>();

        var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            securityPolicy,
            toolTimeoutSeconds: 30,
            approvalTimeoutSeconds: 300
        );

        var correlationContext = new CorrelationContext(Guid.NewGuid());
        var budget = new SessionBudget(maxTokens: 100_000, maxToolCalls: 100);

        return new ManagedSession(
            sessionId: Guid.NewGuid(),
            projectPath: _projectPath,
            externalKey: "telegram:dm:12345",
            orchestrator: orchestrator,
            correlationContext: correlationContext,
            budget: budget,
            sessionAccessStore: null);
    }

    #region Executable Rejection Tests

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectExeFile()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "malicious.exe", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("Executable extension");
        result.Error.Should().Contain(".exe");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectDllFile()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "library.dll", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("Executable extension");
        result.Error.Should().Contain(".dll");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectPs1File()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "script.ps1", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("Executable extension");
        result.Error.Should().Contain(".ps1");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectBatFile()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "script.bat", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("Executable extension");
        result.Error.Should().Contain(".bat");
    }

    #endregion

    #region Double-Extension Bypass Tests

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectDoubleExtension_TxtExe()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "file.txt.exe", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("Executable extension");
        result.Error.Should().Contain(".exe");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectDoubleExtension_JsonBat()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "config.json.bat", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("Executable extension");
        result.Error.Should().Contain(".bat");
    }

    #endregion

    #region File Size Validation Tests

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectFileExceeding10MB()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "large.cs", FileSize = 11 * 1024 * 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("exceeds maximum");
        result.Error.Should().Contain("10MB");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectFileWithMissingSize()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "test.cs", FileSize = null } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("size information is missing");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_AcceptZeroByteFile()
    {
        // Arrange - test edge case of 0-byte file (valid, should not trigger null check)
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "empty.txt", FileSize = 0 } };
        var session = CreateMockSession();

        _accessPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Grant(Path.Combine(_projectPath, ".krutaka-temp"), AccessLevel.ReadWrite));

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert - should pass validation checks (though download will fail without proper mocking)
        // The point is that 0 is not treated as null/missing and passes initial validation
        result.Error.Should().NotContain("size information is missing");
    }

    #endregion

    #region Path Traversal Tests

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectFilenameWithDotDot()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "../../../etc/passwd", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("path traversal");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectFilenameWithForwardSlash()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "subfolder/file.txt", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("path traversal");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectFilenameWithBackslash()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "subfolder\\file.txt", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("path traversal");
    }

    #endregion

    #region Reserved Device Name Tests

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectReservedDeviceName_CON()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "CON.txt", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("reserved device name");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectReservedDeviceName_PRN()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "PRN.log", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("reserved device name");
    }

    [Fact]
    public async Task ReceiveFileAsync_Should_RejectReservedDeviceName_COM1()
    {
        // Arrange
        var message = new Message { Document = new Document { FileId = "test-id", FileName = "COM1.txt", FileSize = 1024 } };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("reserved device name");
    }

    #endregion

    #region No Document Tests

    [Fact]
    public async Task ReceiveFileAsync_Should_ReturnError_WhenNoDocument()
    {
        // Arrange
        var message = new Message { Document = null };
        var session = CreateMockSession();

        // Act
        var result = await _handler.ReceiveFileAsync(message, session, CancellationToken.None);

        // Assert
        result.Success.Should().BeFalse();
        result.Error.Should().Contain("No document found");
    }

    #endregion

    #region Temp Directory Cleanup Tests

    [Fact]
    public async Task RegisterTempDirectoryForCleanup_Should_CleanupOnDispose()
    {
        // Arrange
        var session = CreateMockSession();
        var tempDir = Path.Combine(session.ProjectPath, "test-temp");
        Directory.CreateDirectory(tempDir);
        await System.IO.File.WriteAllTextAsync(Path.Combine(tempDir, "testfile.txt"), "content");

        // Act
        session.RegisterTempDirectoryForCleanup(tempDir);
        await session.DisposeAsync();

        // Assert
        Directory.Exists(tempDir).Should().BeFalse();
    }

    #endregion

    #region SendFileAsync Tests

    [Fact]
    public async Task SendFileAsync_Should_ThrowFileNotFoundException_WhenFileDoesNotExist()
    {
        // Arrange
        var session = CreateMockSession();

        // Act & Assert
        await Assert.ThrowsAsync<FileNotFoundException>(async () =>
            await _handler.SendFileAsync(12345L, "nonexistent.txt", session, null, CancellationToken.None));
    }

    [Fact]
    public async Task SendFileAsync_Should_ThrowArgumentException_WhenFileExceeds50MB()
    {
        // Arrange
        var session = CreateMockSession();
        var largeFile = Path.Combine(_tempTestDir, "large.bin");
        using (var fs = System.IO.File.Create(largeFile))
        {
            fs.SetLength(51 * 1024 * 1024);
        }

        _accessPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Grant(_tempTestDir, AccessLevel.ReadOnly));

        // Act & Assert
        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await _handler.SendFileAsync(12345L, largeFile, session, null, CancellationToken.None));
        ex.Message.Should().Contain("50MB");
    }

    [Fact]
    public async Task SendFileAsync_Should_ThrowUnauthorizedAccessException_WhenAccessDenied()
    {
        // Arrange
        var session = CreateMockSession();
        var testFile = Path.Combine(_tempTestDir, "test.txt");
        await System.IO.File.WriteAllTextAsync(testFile, "Test content");

        _accessPolicyEngine.EvaluateAsync(Arg.Any<DirectoryAccessRequest>(), Arg.Any<CancellationToken>())
            .Returns(AccessDecision.Deny("Access denied by policy"));

        // Act & Assert
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await _handler.SendFileAsync(12345L, testFile, session, null, CancellationToken.None));
    }

    #endregion
}
