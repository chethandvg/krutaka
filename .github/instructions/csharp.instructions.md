# C# Coding Conventions for Krutaka

> **Applies to**: All `**/*.cs` files in the repository  
> **Language**: C# 13 (.NET 10)

## Core Rules

### Nullable Reference Types
- **ALWAYS** enabled (`<Nullable>enable</Nullable>` globally)
- Use `?` for nullable reference types: `string?`, `MyClass?`
- Use `!` null-forgiving operator **only** when absolutely certain the value is not null
- Prefer null-conditional operators: `obj?.Property` and null-coalescing: `value ?? default`

### Async Patterns
- All async methods **MUST** have the `Async` suffix: `ExecuteAsync`, `ReadFileAsync`
- All async methods **MUST** accept `CancellationToken` as the last parameter
- Example:
  ```csharp
  public async Task<string> ReadFileAsync(string path, CancellationToken cancellationToken)
  {
      // implementation
  }
  ```

### Naming Conventions
- **PascalCase**: Public members (methods, properties, classes, interfaces)
  - `public class ToolRegistry`
  - `public string ToolName { get; }`
  - `public void ExecuteTool()`
- **_camelCase**: Private fields
  - `private readonly ILogger _logger;`
  - `private string _apiKey;`
- **camelCase**: Local variables and parameters
  - `string fileName = "test.txt";`
  - `public void Process(string inputData)`
- **IPascalCase**: Interfaces start with `I`
  - `ITool`, `IClaudeClient`, `ISecurityPolicy`

### File Size Limits
- Use `partial class` to split `.cs` files that exceed **300 lines** of code
- Up to **330 lines** is acceptable before requiring a split
- Name partial files descriptively: `MyClass.cs` + `MyClass.Validation.cs`, `MyClass.EventHandlers.cs`
- Keep each partial file focused on a single responsibility or logical grouping

### File-Scoped Namespaces
- **ALWAYS** use file-scoped namespaces (C# 10+ feature):
  ```csharp
  namespace Krutaka.Core;
  
  public class MyClass
  {
      // ...
  }
  ```
- **NEVER** use block-scoped namespaces:
  ```csharp
  // ❌ WRONG
  namespace Krutaka.Core
  {
      public class MyClass { }
  }
  ```

### Implicit Usings
- Enabled globally via `<ImplicitUsings>enable</ImplicitUsings>`
- Common namespaces (`System`, `System.Collections.Generic`, `System.Linq`, etc.) are auto-imported
- Only add `using` for non-implicit namespaces

### Type Inference
- Use `var` when the type is obvious from the right-hand side:
  ```csharp
  var logger = new Logger(); // obvious
  var result = await client.SendAsync(...); // obvious from method name
  ```
- Use explicit types when the type is not obvious:
  ```csharp
  ILogger logger = serviceProvider.GetService<ILogger>(); // clarity needed
  ```

### Pattern Matching
- Prefer `is` and `switch` expressions over traditional patterns:
  ```csharp
  // ✅ GOOD
  if (obj is string text)
  {
      Console.WriteLine(text);
  }
  
  var message = obj switch
  {
      string s => $"String: {s}",
      int i => $"Int: {i}",
      _ => "Unknown"
  };
  
  // ❌ AVOID
  if (obj is string)
  {
      var text = (string)obj;
      Console.WriteLine(text);
  }
  ```

### Collection Expressions
- Use collection expressions `[]` where supported (C# 12+):
  ```csharp
  // ✅ GOOD
  int[] numbers = [1, 2, 3];
  List<string> names = ["Alice", "Bob"];
  
  // ❌ AVOID
  int[] numbers = new int[] { 1, 2, 3 };
  List<string> names = new List<string> { "Alice", "Bob" };
  ```

### String Interpolation
- Prefer string interpolation over `string.Format` or concatenation:
  ```csharp
  // ✅ GOOD
  string message = $"User {userId} logged in at {timestamp}";
  
  // ❌ AVOID
  string message = "User " + userId + " logged in at " + timestamp;
  string message = string.Format("User {0} logged in at {1}", userId, timestamp);
  ```

### Braces
- **ALWAYS** use braces for control statements (enforced by `.editorconfig`):
  ```csharp
  // ✅ GOOD
  if (condition)
  {
      DoSomething();
  }
  
  // ❌ WRONG
  if (condition)
      DoSomething();
  ```

### Error Handling
- **NEVER** swallow exceptions silently
- Log and rethrow, or handle explicitly:
  ```csharp
  // ✅ GOOD
  try
  {
      await ExecuteAsync();
  }
  catch (Exception ex)
  {
      _logger.LogError(ex, "Failed to execute operation");
      throw; // or handle appropriately
  }
  
  // ❌ WRONG
  try
  {
      await ExecuteAsync();
  }
  catch
  {
      // swallowed
  }
  ```
- Wrap `CompactIfNeededAsync()` in try-catch — compaction failure MUST NOT crash the agentic loop
- For recoverable API errors, log and offer recovery; for unrecoverable errors, start new session

### Retry/Resilience Patterns
- Use exponential backoff with jitter for API rate limit retries
- Max 3 retries with exponential backoff (1s, 2s, 4s, 8s, ...) capped at 30s, jitter ±25%
- Parse `retry-after` header from Anthropic responses when available
- After max retries exhausted, propagate the original exception
- Example:
  ```csharp
  for (int attempt = 0; attempt <= maxRetries; attempt++)
  {
      try
      {
          return await ExecuteAsync(cancellationToken);
      }
      catch (AnthropicRateLimitException ex) when (attempt < maxRetries)
      {
          var delay = CalculateBackoffWithJitter(attempt);
          await Task.Delay(delay, cancellationToken);
      }
  }
  ```

### Dependency Injection
- Use constructor injection for all dependencies
- Mark injected fields as `private readonly`:
  ```csharp
  public class MyService
  {
      private readonly ILogger<MyService> _logger;
      private readonly IToolRegistry _tools;
  
      public MyService(ILogger<MyService> logger, IToolRegistry tools)
      {
          _logger = logger;
          _tools = tools;
      }
  }
  ```

### Target-Typed New
- Use `new()` when the type is obvious:
  ```csharp
  // ✅ GOOD
  MyClass instance = new();
  List<string> items = new();
  
  // ❌ AVOID (redundant)
  MyClass instance = new MyClass();
  List<string> items = new List<string>();
  ```

## Security Rules (Non-Negotiable)

### API Keys and Secrets
- **NEVER** hardcode API keys, secrets, or credentials
- Use Windows Credential Manager via `Meziantou.Framework.Win32.CredentialManager`
- **NEVER** log sensitive data

### Path Validation
- All file paths **MUST** be validated through `SafeFileOperations.ValidatePath()`
- Example:
  ```csharp
  string validatedPath = SafeFileOperations.ValidatePath(userProvidedPath, allowedRoot);
  ```

### Command Execution
- All shell commands **MUST** be validated through `CommandPolicy.Validate()`
- **ALWAYS** use CliWrap with explicit argument arrays:
  ```csharp
  // ✅ GOOD
  var result = await Cli.Wrap("git")
      .WithArguments(["status"])
      .ExecuteBufferedAsync(cancellationToken);
  
  // ❌ WRONG (injection risk)
  var result = await Cli.Wrap($"git {userInput}").ExecuteBufferedAsync();
  ```

### Untrusted Content
- Wrap untrusted content in `<untrusted_content>` tags when sending to Claude:
  ```csharp
  string prompt = $"<untrusted_content>{fileContents}</untrusted_content>";
  ```

## Comments
- **DO NOT** add comments unless:
  - They match the style of existing comments in the file
  - They explain complex business logic not obvious from the code
  - They document public API surfaces (use XML doc comments)
- Use XML doc comments for public APIs:
  ```csharp
  /// <summary>
  /// Executes the tool with the provided input.
  /// </summary>
  /// <param name="input">The tool input parameters.</param>
  /// <param name="cancellationToken">Cancellation token.</param>
  /// <returns>The tool execution result.</returns>
  public async Task<string> ExecuteAsync(
      ToolInput input, 
      CancellationToken cancellationToken)
  {
      // implementation
  }
  ```

## EditorConfig Enforcement
- All rules are enforced via `.editorconfig` with `TreatWarningsAsErrors`
- Build **WILL FAIL** on any warning
- Run `dotnet format` to auto-fix formatting issues

## Testing Conventions
- Test class names mirror source class names: `MyClass` → `MyClassTests`
- Test method names use `Should_` prefix: `Should_ReturnTrue_WhenConditionMet`
- Use FluentAssertions for assertions:
  ```csharp
  result.Should().NotBeNull();
  result.Should().BeOfType<string>();
  result.Should().Be("expected value");
  ```

## Multi-Session Patterns

- Per-session mutable state (`AgentOrchestrator`, `CorrelationContext`, `SessionStore`, `ISessionAccessStore`, `ICommandApprovalCache`, `IToolRegistry`) must NEVER be registered as singleton when multi-session is active
- Use `ISessionFactory` to create fully isolated session instances
- Shared stateless services (`IClaudeClient`, `ISecurityPolicy`, `IAuditLogger`, `IAccessPolicyEngine`, `ICommandRiskClassifier`, `ToolOptions`) remain singletons
