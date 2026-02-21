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
    int HeartbeatIntervalMinutes = 5);
