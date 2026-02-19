namespace Krutaka.Core;

/// <summary>
/// Exception thrown by RunCommandTool when command policy evaluation returns RequiresApproval outcome.
/// This exception is caught by the AgentOrchestrator to trigger the interactive approval flow
/// with tier-aware prompts.
/// </summary>
public sealed class CommandApprovalRequiredException : Exception
{
    /// <summary>
    /// Gets the command execution request that requires approval.
    /// </summary>
    public CommandExecutionRequest Request { get; }

    /// <summary>
    /// Gets the policy decision for this command.
    /// </summary>
    public CommandDecision Decision { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandApprovalRequiredException"/> class.
    /// This is a required constructor for exception serialization but should not be used directly.
    /// </summary>
    public CommandApprovalRequiredException()
        : base("Command execution requires approval")
    {
        Request = new CommandExecutionRequest(
            Executable: string.Empty,
            Arguments: Array.Empty<string>(),
            WorkingDirectory: null,
            Justification: string.Empty);
        Decision = CommandDecision.RequireApproval(CommandRiskTier.Safe, "Default");
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandApprovalRequiredException"/> class with a message.
    /// This is a required constructor for exception serialization but should not be used directly.
    /// </summary>
    /// <param name="message">The exception message.</param>
    public CommandApprovalRequiredException(string message)
        : base(message)
    {
        Request = new CommandExecutionRequest(
            Executable: string.Empty,
            Arguments: Array.Empty<string>(),
            WorkingDirectory: null,
            Justification: string.Empty);
        Decision = CommandDecision.RequireApproval(CommandRiskTier.Safe, "Default");
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandApprovalRequiredException"/> class with a message and inner exception.
    /// This is a required constructor for exception serialization but should not be used directly.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <param name="innerException">The inner exception.</param>
    public CommandApprovalRequiredException(string message, Exception? innerException)
        : base(message, innerException)
    {
        Request = new CommandExecutionRequest(
            Executable: string.Empty,
            Arguments: Array.Empty<string>(),
            WorkingDirectory: null,
            Justification: string.Empty);
        Decision = CommandDecision.RequireApproval(CommandRiskTier.Safe, "Default");
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandApprovalRequiredException"/> class.
    /// </summary>
    /// <param name="request">The command execution request requiring approval.</param>
    /// <param name="decision">The policy decision for this command.</param>
    public CommandApprovalRequiredException(CommandExecutionRequest request, CommandDecision decision)
        : base(BuildMessage(request, decision))
    {
        if (!decision.RequiresApproval)
        {
            throw new ArgumentException("Decision must have RequiresApproval outcome", nameof(decision));
        }

        Request = request;
        Decision = decision;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandApprovalRequiredException"/> class with an inner exception.
    /// </summary>
    /// <param name="request">The command execution request requiring approval.</param>
    /// <param name="decision">The policy decision for this command.</param>
    /// <param name="innerException">The inner exception.</param>
    public CommandApprovalRequiredException(CommandExecutionRequest request, CommandDecision decision, Exception? innerException)
        : base(BuildMessage(request, decision), innerException)
    {
        if (!decision.RequiresApproval)
        {
            throw new ArgumentException("Decision must have RequiresApproval outcome", nameof(decision));
        }

        Request = request;
        Decision = decision;
    }

    /// <summary>
    /// Builds the exception message from the request and decision.
    /// Validates arguments are non-null before using them.
    /// </summary>
    private static string BuildMessage(CommandExecutionRequest request, CommandDecision decision)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(decision);
        
        return $"Command execution requires approval: {request.Executable} {string.Join(" ", request.Arguments)} (Tier: {decision.Tier}, Reason: {decision.Reason})";
    }
}
