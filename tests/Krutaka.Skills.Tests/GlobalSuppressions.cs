// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

// Allow underscores in test method names (common xUnit convention)
[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Standard xUnit test naming convention", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Skills.Tests")]

// Allow unsealed test classes (for potential test inheritance)
[assembly: SuppressMessage("Performance", "CA1852:Seal internal types", Justification = "Test classes may be inherited in future", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Skills.Tests")]

// Allow constant array arguments in tests (test data is not performance-critical)
[assembly: SuppressMessage("Performance", "CA1861:Avoid constant arrays as arguments", Justification = "Test data arrays are simple and not performance-critical", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Skills.Tests")]

// Suppress CA2007 in test code - ConfigureAwait is not needed in tests and conflicts with xUnit1030
[assembly: SuppressMessage("Reliability", "CA2007:Consider calling ConfigureAwait on the awaited task", Justification = "ConfigureAwait is not needed in test code and conflicts with xUnit analyzer xUnit1030", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Skills.Tests")]

// Suppress CA1063 for test fixture classes using IDisposable
[assembly: SuppressMessage("Design", "CA1063:Implement IDisposable Correctly", Justification = "Test fixtures only need simple Dispose for cleanup, not full IDisposable pattern", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Skills.Tests")]
