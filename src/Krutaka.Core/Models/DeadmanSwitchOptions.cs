namespace Krutaka.Core;

/// <summary>
/// Configuration for the deadman's switch timer that monitors user interaction per session.
/// When enabled, the agent is automatically paused after <see cref="MaxUnattendedMinutes"/> of
/// inactivity, and aborted at 2× that duration if no user interaction resumes it.
/// </summary>
/// <param name="MaxUnattendedMinutes">
/// Maximum minutes without user interaction before the agent is paused.
/// Set to 0 to disable the deadman's switch entirely. Default is 30.
/// </param>
/// <param name="HeartbeatIntervalMinutes">
/// Reserved for future use. Interval in minutes between liveness checks. Default is 5.
/// </param>
public sealed record DeadmanSwitchOptions(
    int MaxUnattendedMinutes = 30,
    int HeartbeatIntervalMinutes = 5)
{
    /// <summary>
    /// Gets the validated maximum unattended minutes. 0 disables the switch; negative values are invalid.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <see cref="MaxUnattendedMinutes"/> is negative.</exception>
    public int MaxUnattendedMinutes { get; init; } = ValidateNonNegative(MaxUnattendedMinutes, nameof(MaxUnattendedMinutes));

    /// <summary>
    /// Gets the validated heartbeat interval minutes. Negative values are invalid.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <see cref="HeartbeatIntervalMinutes"/> is negative.</exception>
    public int HeartbeatIntervalMinutes { get; init; } = ValidateNonNegative(HeartbeatIntervalMinutes, nameof(HeartbeatIntervalMinutes));

    private static int ValidateNonNegative(int value, string paramName)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value, paramName);
        return value;
    }
}
