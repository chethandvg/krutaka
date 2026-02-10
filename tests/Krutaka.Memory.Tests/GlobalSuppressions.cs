using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Standard xUnit test naming convention", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Memory.Tests")]
[assembly: SuppressMessage("Reliability", "CA2007:Consider calling ConfigureAwait on the awaited task", Justification = "Test code does not need ConfigureAwait", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Memory.Tests")]
