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
    /// Runs the long polling loop with hardened security mitigations.
    /// </summary>
    private async Task RunLongPollingLoopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting long polling loop with timeout {TimeoutSeconds}s", _config.PollingTimeoutSeconds);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // Poll for updates
                var updates = await _botClient.GetUpdates(
                    offset: _lastProcessedUpdateId + 1,
                    timeout: _config.PollingTimeoutSeconds,
                    allowedUpdates: [UpdateType.Message, UpdateType.CallbackQuery],
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                if (updates.Length == 0)
                {
                    // No updates, reset backoff on successful poll
                    if (_consecutiveFailures > 0)
                    {
                        _consecutiveFailures = 0;
                        _currentBackoffSeconds = InitialBackoffSeconds;
                        _logger.LogInformation("Polling resumed successfully, backoff reset");
                    }

                    continue;
                }

                // Kill switch priority: check for /killswitch BEFORE processing any other command
                // Use normalized command detection to handle @BotName mentions in group chats
                var killSwitchUpdate = updates.FirstOrDefault(u => IsKillSwitchCommand(u.Message?.Text));

                bool killSwitchExecuted = false;
                if (killSwitchUpdate is not null)
                {
                    _logger.LogCritical("Kill switch command detected in batch, processing immediately");

                    // Validate and process kill switch - only exit if it was actually executed
                    var authResult = await _authGuard.ValidateAsync(killSwitchUpdate, cancellationToken).ConfigureAwait(false);
                    if (authResult.IsValid)
                    {
                        var routeResult = await _router.RouteAsync(killSwitchUpdate, authResult, cancellationToken).ConfigureAwait(false);
                        if (routeResult.Routed && routeResult.Command == TelegramCommand.KillSwitch)
                        {
                            await HandleKillSwitchAsync(authResult.ChatId, cancellationToken).ConfigureAwait(false);
                            killSwitchExecuted = true;

                            // Commit offset for kill switch before exiting
                            // Make one more poll to confirm the offset with Telegram
                            _lastProcessedUpdateId = killSwitchUpdate.Id;
                            try
                            {
                                await _botClient.GetUpdates(
                                    offset: _lastProcessedUpdateId + 1,
                                    timeout: 0,
                                    cancellationToken: cancellationToken).ConfigureAwait(false);
                            }
#pragma warning disable CA1031 // Ignore all errors during final offset confirmation before shutdown
                            catch
#pragma warning restore CA1031
                            {
                                // Ignore errors during final offset confirmation
                            }

                            // Exit polling loop - app shutdown initiated
                            return;
                        }
                    }
                }

                // Process updates sequentially
                foreach (var update in updates)
                {
                    // Skip kill switch if already processed
                    if (killSwitchUpdate is not null && update.Id == killSwitchUpdate.Id && killSwitchExecuted)
                    {
                        continue;
                    }

                    var success = await ProcessUpdateAsync(update, cancellationToken).ConfigureAwait(false);

                    // Commit offset AFTER successful processing (offset-after-processing mitigation)
                    // Only advance if processing succeeded to allow retry on transient failures
                    if (success)
                    {
                        _lastProcessedUpdateId = update.Id;
                    }
                    else
                    {
                        _logger.LogWarning("Update {UpdateId} processing failed, will retry on next poll", update.Id);
                        break; // Stop processing this batch, will retry failed update and remaining updates
                    }
                }

                // Reset backoff on successful batch processing
                if (_consecutiveFailures > 0)
                {
                    _consecutiveFailures = 0;
                    _currentBackoffSeconds = InitialBackoffSeconds;
                    _logger.LogInformation("Polling resumed successfully after failures, backoff reset");
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown, don't count as failure
                throw;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _consecutiveFailures++;
                _logger.LogError(ex, "Polling error (consecutive failures: {Count})", _consecutiveFailures);

                // Stop polling after max consecutive failures
                if (_consecutiveFailures >= MaxConsecutiveFailures)
                {
                    _logger.LogCritical(
                        "Reached maximum consecutive failures ({Max}), stopping polling loop",
                        MaxConsecutiveFailures);
                    break;
                }

                // Exponential backoff with cap
                var delaySeconds = Math.Min(_currentBackoffSeconds, MaxRetryBackoffSeconds);
                _logger.LogWarning("Backing off for {Seconds}s before retry", delaySeconds);

                await Task.Delay(TimeSpan.FromSeconds(delaySeconds), cancellationToken).ConfigureAwait(false);

                // Double the backoff for next failure (exponential)
                _currentBackoffSeconds = Math.Min(_currentBackoffSeconds * 2, MaxRetryBackoffSeconds);
            }
        }

        _logger.LogInformation("Long polling loop exited");
    }

    /// <summary>
    /// Checks if a message text represents the kill switch command.
    /// Handles @BotName mentions in group chats by normalizing the command.
    /// </summary>
    private bool IsKillSwitchCommand(string? messageText)
    {
        if (string.IsNullOrWhiteSpace(messageText))
        {
            return false;
        }

        var trimmed = messageText.Trim();

        // Fast path: exact match
        if (trimmed.Equals(_config.PanicCommand, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var panicCommand = _config.PanicCommand?.Trim() ?? string.Empty;
        if (panicCommand.Length == 0)
        {
            return false;
        }

        // Extract command token (before any arguments or whitespace)
        var spaceIndex = trimmed.IndexOf(' ', StringComparison.Ordinal);
        var commandToken = spaceIndex >= 0 ? trimmed[..spaceIndex] : trimmed;

        // Strip optional @BotName mention (e.g., "/killswitch@MyBot" -> "/killswitch")
        var atIndex = commandToken.IndexOf('@', StringComparison.Ordinal);
        if (atIndex >= 0)
        {
            commandToken = commandToken[..atIndex];
        }

        return commandToken.Equals(panicCommand, StringComparison.OrdinalIgnoreCase);
    }
}
