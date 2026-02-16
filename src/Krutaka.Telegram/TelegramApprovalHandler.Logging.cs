using Microsoft.Extensions.Logging;

namespace Krutaka.Telegram;

/// <summary>
/// TelegramApprovalHandler - Logging partial.
/// </summary>
public sealed partial class TelegramApprovalHandler
{
    [LoggerMessage(Level = LogLevel.Warning, Message = "Received callback with missing data, from, or message")]
    partial void LogCallbackMissingData();

    [LoggerMessage(Level = LogLevel.Warning, Message = "HMAC verification failed for callback from user {UserId}")]
    partial void LogHmacVerificationFailed(long userId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "User {ActualUserId} attempted to approve callback for user {ExpectedUserId}")]
    partial void LogUserIdMismatch(long actualUserId, long expectedUserId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Expired callback from user {UserId} (age: {Age}s)")]
    partial void LogExpiredCallback(long userId, long age);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Replay attack detected: nonce {Nonce} already used by user {UserId}")]
    partial void LogReplayAttempt(string nonce, long userId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Session {SessionId} not found for callback from user {UserId}")]
    partial void LogSessionNotFound(Guid sessionId, long userId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Unknown approval action: {Action}")]
    partial void LogUnknownAction(string action);

    [LoggerMessage(Level = LogLevel.Information, Message = "Approval processed: {Action} by user {UserId} for session {SessionId}")]
    partial void LogApprovalProcessed(string action, long userId, Guid sessionId);

    [LoggerMessage(Level = LogLevel.Error, Message = "Error processing approval callback for session {SessionId}")]
    partial void LogCallbackProcessingError(Exception ex, Guid sessionId);

    [LoggerMessage(Level = LogLevel.Error, Message = "Error answering callback query")]
    partial void LogAnswerCallbackError(Exception ex);

    [LoggerMessage(Level = LogLevel.Error, Message = "Error editing message to expired")]
    partial void LogEditMessageError(Exception ex);

    [LoggerMessage(Level = LogLevel.Error, Message = "Error logging security incident")]
    partial void LogAuditLoggingError(Exception ex);

    [LoggerMessage(Level = LogLevel.Information, Message = "Approval timeout for session {SessionId}")]
    partial void LogApprovalTimeout(Guid sessionId);

    [LoggerMessage(Level = LogLevel.Error, Message = "Error handling approval timeout for session {SessionId}")]
    partial void LogTimeoutHandlingError(Exception ex, Guid sessionId);
}
