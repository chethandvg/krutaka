// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

// Allow underscores in test method names (common xUnit convention)
[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Standard xUnit test naming convention", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Tools.Tests")]

// Allow unsealed test classes (for potential test inheritance)
[assembly: SuppressMessage("Performance", "CA1852:Seal internal types", Justification = "Test classes may be inherited in future", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Tools.Tests")]
