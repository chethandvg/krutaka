using Krutaka.Core;
using Microsoft.Extensions.Logging;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;

#pragma warning disable CA1848 // Use LoggerMessage delegates for improved performance
#pragma warning disable CA1873 // Evaluation of logging arguments may be expensive when logging is disabled

namespace Krutaka.Telegram;

public sealed partial class TelegramBotService
{
    /// <summary>
    /// Handles the /checkpoint command — creates a manual git checkpoint for the user's session.
    /// </summary>
    private async Task HandleCheckpointCommandAsync(
        AuthResult authResult,
        Update update,
        CancellationToken cancellationToken)
    {
        try
        {
            var session = await GetSessionAndNotifyAsync(authResult, update, cancellationToken).ConfigureAwait(false);

            var checkpointService = session.GitCheckpointService;
            if (checkpointService is null)
            {
                await _botClient.SendMessage(
                    authResult.ChatId,
                    "⚠️ Checkpoints not available — not a git repository",
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                return;
            }

            var checkpointId = await checkpointService.CreateCheckpointAsync("Manual checkpoint", cancellationToken).ConfigureAwait(false);

            string message;
            if (string.IsNullOrEmpty(checkpointId))
            {
                message = "⚠️ Nothing to checkpoint — working tree is clean or repository has no commits";
            }
            else
            {
                var escapedId = EscapeMarkdownV2(checkpointId);
                message = $"✅ Checkpoint created: `{escapedId}`\n_Manual checkpoint_";
            }

            await _botClient.SendMessage(
                authResult.ChatId,
                message,
                parseMode: ParseMode.MarkdownV2,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            _logger.LogInformation("Manual checkpoint created for chat {ChatId}: {CheckpointId}", authResult.ChatId, checkpointId);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error handling checkpoint command for chat {ChatId}", authResult.ChatId);

            await _botClient.SendMessage(
                authResult.ChatId,
                $"❌ Failed to create checkpoint: {ex.Message}",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Handles the /rollback command — rolls back to a previous git checkpoint.
    /// </summary>
    private async Task HandleRollbackCommandAsync(
        CommandRouteResult routeResult,
        AuthResult authResult,
        Update update,
        CancellationToken cancellationToken)
    {
        try
        {
            var session = await GetSessionAndNotifyAsync(authResult, update, cancellationToken).ConfigureAwait(false);

            var checkpointService = session.GitCheckpointService;
            if (checkpointService is null)
            {
                await _botClient.SendMessage(
                    authResult.ChatId,
                    "⚠️ Checkpoints not available — not a git repository",
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                return;
            }

            var checkpoints = await checkpointService.ListCheckpointsAsync(cancellationToken).ConfigureAwait(false);

            var argument = routeResult.Arguments?.Trim();

            if (string.IsNullOrWhiteSpace(argument))
            {
                // No argument — show list with usage instructions
                if (checkpoints.Count == 0)
                {
                    await _botClient.SendMessage(
                        authResult.ChatId,
                        "ℹ️ No checkpoints available for this session\\.",
                        parseMode: ParseMode.MarkdownV2,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    return;
                }

                var sb = new System.Text.StringBuilder();
                sb.AppendLine("📋 *Available Checkpoints*\n");
                foreach (var cp in checkpoints)
                {
                    sb.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"• `{EscapeMarkdownV2(cp.CheckpointId)}` — {EscapeMarkdownV2(cp.Message)}");
                }

                sb.AppendLine();
                sb.AppendLine("Use `/rollback <id>` or `/rollback latest` to roll back\\.");

                await _botClient.SendMessage(
                    authResult.ChatId,
                    sb.ToString(),
                    parseMode: ParseMode.MarkdownV2,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                return;
            }

            // Resolve target checkpoint
            CheckpointInfo? target;
            if (argument.Equals("latest", StringComparison.OrdinalIgnoreCase))
            {
                if (checkpoints.Count == 0)
                {
                    await _botClient.SendMessage(
                        authResult.ChatId,
                        "⚠️ No checkpoints available for this session\\.",
                        parseMode: ParseMode.MarkdownV2,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    return;
                }

                target = checkpoints[^1];
            }
            else
            {
                target = checkpoints.FirstOrDefault(cp => cp.CheckpointId.Equals(argument, StringComparison.OrdinalIgnoreCase));
                if (target is null)
                {
                    await _botClient.SendMessage(
                        authResult.ChatId,
                        $"⚠️ Checkpoint `{EscapeMarkdownV2(argument)}` not found\\.",
                        parseMode: ParseMode.MarkdownV2,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                    return;
                }
            }

            await checkpointService.RollbackToCheckpointAsync(target.CheckpointId, cancellationToken).ConfigureAwait(false);

            await _botClient.SendMessage(
                authResult.ChatId,
                $"✅ Rolled back to `{EscapeMarkdownV2(target.CheckpointId)}`",
                parseMode: ParseMode.MarkdownV2,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            _logger.LogInformation("Rolled back to checkpoint {CheckpointId} for chat {ChatId}", target.CheckpointId, authResult.ChatId);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error handling rollback command for chat {ChatId}", authResult.ChatId);

            await _botClient.SendMessage(
                authResult.ChatId,
                $"❌ Failed to rollback: {ex.Message}",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Escapes a string for use in Telegram MarkdownV2 format.
    /// </summary>
    private static string EscapeMarkdownV2(string text)
    {
        return text.Replace("_", "\\_", StringComparison.Ordinal)
                   .Replace("*", "\\*", StringComparison.Ordinal)
                   .Replace("[", "\\[", StringComparison.Ordinal)
                   .Replace("]", "\\]", StringComparison.Ordinal)
                   .Replace("(", "\\(", StringComparison.Ordinal)
                   .Replace(")", "\\)", StringComparison.Ordinal)
                   .Replace("~", "\\~", StringComparison.Ordinal)
                   .Replace(">", "\\>", StringComparison.Ordinal)
                   .Replace("#", "\\#", StringComparison.Ordinal)
                   .Replace("+", "\\+", StringComparison.Ordinal)
                   .Replace("-", "\\-", StringComparison.Ordinal)
                   .Replace("=", "\\=", StringComparison.Ordinal)
                   .Replace("|", "\\|", StringComparison.Ordinal)
                   .Replace("{", "\\{", StringComparison.Ordinal)
                   .Replace("}", "\\}", StringComparison.Ordinal)
                   .Replace(".", "\\.", StringComparison.Ordinal)
                   .Replace("!", "\\!", StringComparison.Ordinal);
    }
}
