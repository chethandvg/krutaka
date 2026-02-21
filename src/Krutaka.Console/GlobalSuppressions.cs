// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.

using System.Diagnostics.CodeAnalysis;

// LogRedactionEnricher needs to be public for testing purposes
[assembly: SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Required for unit testing", Scope = "type", Target = "~T:Krutaka.Console.Logging.LogRedactionEnricher")]

// ConsoleUI methods are instance methods as they are part of a stateful, disposable object with lifecycle management
[assembly: SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Methods are part of instance lifecycle and state management", Scope = "member", Target = "~M:Krutaka.Console.ConsoleUI.DisplayBanner")]
[assembly: SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Methods are part of instance lifecycle and state management", Scope = "member", Target = "~M:Krutaka.Console.ConsoleUI.GetUserInput")]
[assembly: SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Methods are part of instance lifecycle and state management", Scope = "member", Target = "~M:Krutaka.Console.ConsoleUI.DisplayError(System.String)")]
[assembly: SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Methods are part of instance lifecycle and state management", Scope = "member", Target = "~M:Krutaka.Console.ConsoleUI.DisplayHelp")]
[assembly: SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Methods are part of instance lifecycle and state management", Scope = "member", Target = "~M:Krutaka.Console.ConsoleUI.DisplayMemoryStats(Krutaka.Console.MemoryStats)")]
[assembly: SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Methods are part of instance lifecycle and state management", Scope = "member", Target = "~M:Krutaka.Console.ConsoleUI.DisplaySessionInfo(Krutaka.Console.SessionInfo)")]
[assembly: SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Methods are part of instance lifecycle and state management", Scope = "member", Target = "~M:Krutaka.Console.ConsoleUI.DisplayCompactionResult(System.Int32,System.Int32)")]
[assembly: SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Methods are part of instance lifecycle and state management", Scope = "member", Target = "~M:Krutaka.Console.ConsoleUI.DisplayAutonomyLevel(Krutaka.Core.IAutonomyLevelProvider)")]
