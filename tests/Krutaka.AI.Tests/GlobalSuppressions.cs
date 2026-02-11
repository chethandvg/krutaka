// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Reliability", "CA2007:Consider calling ConfigureAwait on the awaited task", Justification = "xUnit test methods should not use ConfigureAwait(false)")]

// Allow underscores in test method names (common xUnit convention)
[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Standard xUnit test naming convention", Scope = "namespaceanddescendants", Target = "~N:Krutaka.AI.Tests")]

// Allow unsealed test classes (for potential test inheritance)
[assembly: SuppressMessage("Performance", "CA1852:Seal internal types", Justification = "Test classes may be inherited in future", Scope = "namespaceanddescendants", Target = "~N:Krutaka.AI.Tests")]
