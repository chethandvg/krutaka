using System.Globalization;
using System.Security;
using FluentAssertions;
using Krutaka.Core;
using NSubstitute;
using Xunit;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Integration tests for security violation logging through IFileOperations and ISecurityPolicy.
/// </summary>
public class SecurityViolationLoggingTests
{
    [Fact]
    public void SafeFileOperations_Should_LogPathViolation_WhenAuditLoggerProvided()
    {
        // Arrange
        var mockAuditLogger = Substitute.For<IAuditLogger>();
        var sessionId = Guid.NewGuid();
        var correlationContext = new CorrelationContext(sessionId);
        correlationContext.IncrementTurn();
        var fileOps = new SafeFileOperations(mockAuditLogger);
        var testRoot = "/tmp/test";
        var blockedPath = "../../../etc/passwd"; // Path traversal attempt

        // Act
        var act = () => fileOps.ValidatePath(blockedPath, testRoot, correlationContext);

        // Assert
        act.Should().Throw<SecurityException>();
        mockAuditLogger.Received(1).LogSecurityViolation(
            Arg.Is<CorrelationContext>(ctx => ctx.SessionId == correlationContext.SessionId && ctx.TurnId == correlationContext.TurnId),
            "blocked_path",
            Arg.Any<string>(),
            Arg.Is<string>(msg => msg.Contains("Path traversal", StringComparison.Ordinal) || msg.Contains("outside the allowed root", StringComparison.Ordinal)));
    }

    [Fact]
    public void SafeFileOperations_Should_NotLog_WhenAuditLoggerNotProvided()
    {
        // Arrange
        var fileOps = new SafeFileOperations(null); // No audit logger
        var testRoot = "/tmp/test";
        var blockedPath = "../../../etc/passwd"; // Path traversal attempt

        // Act
        var act = () => fileOps.ValidatePath(blockedPath, testRoot, null);

        // Assert
        act.Should().Throw<SecurityException>(); // Should still throw, just not log
    }

    [Fact]
    public void SafeFileOperations_Should_LogFileSizeViolation_WhenAuditLoggerProvided()
    {
        // Arrange
        var mockAuditLogger = Substitute.For<IAuditLogger>();
        var sessionId = Guid.NewGuid();
        var correlationContext = new CorrelationContext(sessionId);
        correlationContext.IncrementTurn();
        var fileOps = new SafeFileOperations(mockAuditLogger);
        
        // Create a temp file larger than the limit
        var tempFile = Path.GetTempFileName();
        try
        {
            // Write more than 1MB
            using (var fs = new FileStream(tempFile, FileMode.Create))
            {
                var buffer = new byte[fileOps.MaxFileSizeBytes + 1000];
                fs.Write(buffer, 0, buffer.Length);
            }

            // Act
            var act = () => fileOps.ValidateFileSize(tempFile, correlationContext);

            // Assert
            act.Should().Throw<SecurityException>();
            mockAuditLogger.Received(1).LogSecurityViolation(
                Arg.Is<CorrelationContext>(ctx => ctx.SessionId == correlationContext.SessionId),
                "blocked_file_size",
                Arg.Any<string>(),
                Arg.Is<string>(msg => msg.Contains("exceeds maximum", StringComparison.Ordinal)));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public void CommandPolicy_Should_LogCommandViolation_WhenAuditLoggerProvided()
    {
        // Arrange
        var mockAuditLogger = Substitute.For<IAuditLogger>();
        var mockFileOps = Substitute.For<IFileOperations>();
        var sessionId = Guid.NewGuid();
        var correlationContext = new CorrelationContext(sessionId);
        correlationContext.IncrementTurn();
        var policy = new CommandPolicy(mockFileOps, mockAuditLogger);
        var blockedCommand = "powershell";
        var args = new[] { "-Command", "Get-Process" };

        // Act
        var act = () => policy.ValidateCommand(blockedCommand, args, correlationContext);

        // Assert
        act.Should().Throw<SecurityException>();
        mockAuditLogger.Received(1).LogSecurityViolation(
            Arg.Is<CorrelationContext>(ctx => ctx.SessionId == correlationContext.SessionId),
            "blocked_command",
            Arg.Any<string>(),
            Arg.Is<string>(msg => msg.Contains("not permitted", StringComparison.Ordinal)));
    }

    [Fact]
    public void CommandPolicy_Should_LogShellMetacharacterViolation_WhenAuditLoggerProvided()
    {
        // Arrange
        var mockAuditLogger = Substitute.For<IAuditLogger>();
        var mockFileOps = Substitute.For<IFileOperations>();
        var sessionId = Guid.NewGuid();
        var correlationContext = new CorrelationContext(sessionId);
        correlationContext.IncrementTurn();
        var policy = new CommandPolicy(mockFileOps, mockAuditLogger);
        var command = "git";
        var argsWithShellChars = new[] { "status", "; rm -rf /" };

        // Act
        var act = () => policy.ValidateCommand(command, argsWithShellChars, correlationContext);

        // Assert
        act.Should().Throw<SecurityException>();
        mockAuditLogger.Received(1).LogSecurityViolation(
            Arg.Is<CorrelationContext>(ctx => ctx.SessionId == correlationContext.SessionId),
            "blocked_command_argument",
            Arg.Is<string>(val => val.Contains(';')),
            Arg.Is<string>(msg => msg.Contains("shell metacharacters", StringComparison.Ordinal)));
    }

    [Fact]
    public void CommandPolicy_Should_NotLog_WhenAuditLoggerNotProvided()
    {
        // Arrange
        var fileOps = new SafeFileOperations(null);
        var policy = new CommandPolicy(fileOps, null); // No audit logger
        var blockedCommand = "powershell";
        var args = new[] { "-Command", "Get-Process" };

        // Act
        var act = () => policy.ValidateCommand(blockedCommand, args, null);

        // Assert
        act.Should().Throw<SecurityException>(); // Should still throw, just not log
    }

    [Fact]
    public void SafeFileOperations_Should_NotLog_WhenCorrelationContextNotProvided()
    {
        // Arrange
        var mockAuditLogger = Substitute.For<IAuditLogger>();
        var fileOps = new SafeFileOperations(mockAuditLogger);
        var testRoot = "/tmp/test";
        var blockedPath = "../../../etc/passwd"; // Path traversal attempt

        // Act
        var act = () => fileOps.ValidatePath(blockedPath, testRoot, null); // No correlation context

        // Assert
        act.Should().Throw<SecurityException>();
        mockAuditLogger.DidNotReceive().LogSecurityViolation(
            Arg.Any<CorrelationContext>(),
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<string>());
    }

    [Fact]
    public void CommandPolicy_Should_NotLog_WhenCorrelationContextNotProvided()
    {
        // Arrange
        var mockAuditLogger = Substitute.For<IAuditLogger>();
        var mockFileOps = Substitute.For<IFileOperations>();
        var policy = new CommandPolicy(mockFileOps, mockAuditLogger);
        var blockedCommand = "powershell";
        var args = new[] { "-Command", "Get-Process" };

        // Act
        var act = () => policy.ValidateCommand(blockedCommand, args, null); // No correlation context

        // Assert
        act.Should().Throw<SecurityException>();
        mockAuditLogger.DidNotReceive().LogSecurityViolation(
            Arg.Any<CorrelationContext>(),
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<string>());
    }
}
