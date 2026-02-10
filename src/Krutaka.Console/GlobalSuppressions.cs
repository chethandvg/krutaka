// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.

using System.Diagnostics.CodeAnalysis;

// LogRedactionEnricher needs to be public for testing purposes
[assembly: SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Required for unit testing", Scope = "type", Target = "~T:Krutaka.Console.Logging.LogRedactionEnricher")]
