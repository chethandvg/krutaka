namespace Krutaka.Core;

/// <summary>
/// Exception thrown by tools when directory access evaluation returns RequiresApproval outcome.
/// This exception is caught by the AgentOrchestrator to trigger the interactive approval flow.
/// </summary>
public sealed class DirectoryAccessRequiredException : Exception
{
    /// <summary>
    /// Gets the directory path that requires approval.
    /// </summary>
    public string Path { get; }

    /// <summary>
    /// Gets the access level being requested.
    /// </summary>
    public AccessLevel RequestedLevel { get; }

    /// <summary>
    /// Gets the justification for the access request.
    /// </summary>
    public string Justification { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryAccessRequiredException"/> class.
    /// This is a required constructor for exception serialization but should not be used directly.
    /// </summary>
    public DirectoryAccessRequiredException()
        : base("Directory access requires approval")
    {
        Path = string.Empty;
        RequestedLevel = AccessLevel.ReadOnly;
        Justification = string.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryAccessRequiredException"/> class with a message.
    /// This is a required constructor for exception serialization but should not be used directly.
    /// </summary>
    /// <param name="message">The exception message.</param>
    public DirectoryAccessRequiredException(string message)
        : base(message)
    {
        Path = string.Empty;
        RequestedLevel = AccessLevel.ReadOnly;
        Justification = string.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryAccessRequiredException"/> class with a message and inner exception.
    /// This is a required constructor for exception serialization but should not be used directly.
    /// </summary>
    /// <param name="message">The exception message.</param>
    /// <param name="innerException">The inner exception.</param>
    public DirectoryAccessRequiredException(string message, Exception? innerException)
        : base(message, innerException)
    {
        Path = string.Empty;
        RequestedLevel = AccessLevel.ReadOnly;
        Justification = string.Empty;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryAccessRequiredException"/> class.
    /// </summary>
    /// <param name="path">The directory path requiring approval.</param>
    /// <param name="requestedLevel">The requested access level.</param>
    /// <param name="justification">The justification for the request.</param>
    public DirectoryAccessRequiredException(string path, AccessLevel requestedLevel, string justification)
        : base($"Directory access requires approval: {path} (Level: {requestedLevel})")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(justification);

        Path = path;
        RequestedLevel = requestedLevel;
        Justification = justification;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryAccessRequiredException"/> class with an inner exception.
    /// </summary>
    /// <param name="path">The directory path requiring approval.</param>
    /// <param name="requestedLevel">The requested access level.</param>
    /// <param name="justification">The justification for the request.</param>
    /// <param name="innerException">The inner exception.</param>
    public DirectoryAccessRequiredException(string path, AccessLevel requestedLevel, string justification, Exception? innerException)
        : base($"Directory access requires approval: {path} (Level: {requestedLevel})", innerException)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(justification);

        Path = path;
        RequestedLevel = requestedLevel;
        Justification = justification;
    }
}
