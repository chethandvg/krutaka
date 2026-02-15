// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.

using System.Diagnostics.CodeAnalysis;

// Allow underscores in test method names (common xUnit convention)
[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Standard xUnit test naming convention", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Console.Tests")]

// Allow unsealed test classes (for potential test inheritance)
[assembly: SuppressMessage("Performance", "CA1852:Seal internal types", Justification = "Test classes may be inherited in future", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Console.Tests")]

// Allow mock classes that appear uninstantiated
[assembly: SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Mock classes are instantiated via reflection or DI", Scope = "namespaceanddescendants", Target = "~N:Krutaka.Console.Tests")]
