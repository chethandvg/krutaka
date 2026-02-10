# Building an OpenClaw-style AI agent in C#/.NET 8+

**The Anthropic.SDK library (v5.9.0), combined with SQLite for hybrid memory, Spectre.Console for the terminal UI, and a clean architecture split across five projects, gives you everything needed to build a fully local, console-based agentic system on Windows.** The ecosystem has matured rapidly — an official Anthropic C# SDK now exists (beta), `Microsoft.Extensions.AI` provides a provider-agnostic abstraction layer, and local ONNX embedding models eliminate any need for external vector databases. This blueprint covers every component: the API integration layer, the agentic tool loop, persistent memory with hybrid search, session management, a skills/plugin system, security hardening, and the console interaction layer — all with concrete code patterns.

---

## 1. Claude API integration: two strong options, one clear winner

The C# ecosystem for Claude now offers two viable libraries. The **official `Anthropic` NuGet package** (v12.3.0, from `anthropics/anthropic-sdk-csharp`) is in beta, supports streaming via `CreateStreaming` returning `IAsyncEnumerable`, and integrates with the `IChatClient` interface from `Microsoft.Extensions.AI.Abstractions`. The **community `Anthropic.SDK`** by tghamm (v5.9.0, **202 GitHub stars**) is more mature, targets .NET 8.0 and .NET 10.0, and offers Semantic Kernel integration, extended thinking, prompt caching, MCP connectors, and — critically — `UseFunctionInvocation()` which automates the entire agentic tool loop via `IChatClient`.

**Recommended choice: `Anthropic.SDK`** for this project. It handles streaming (`StreamClaudeMessageAsync`), has first-class tool use support with both the native API and the `IChatClient` abstraction, and its `UseFunctionInvocation()` decorator eliminates boilerplate. The Cysharp `Claudia` library was archived in November 2025 and should not be used for new projects.

The key NuGet packages for the API layer:

```xml
<PackageReference Include="Anthropic.SDK" Version="5.9.0" />
<PackageReference Include="Microsoft.Extensions.AI" Version="*-*" />
<PackageReference Include="System.Net.ServerSentEvents" Version="10.0.0" />
```

### Claude's tool use protocol in detail

Every API request includes a `tools` array where each tool specifies a `name` (regex `^[a-zA-Z0-9_-]{1,64}$`), a `description` (3-4+ sentences recommended), and an `input_schema` conforming to JSON Schema. When Claude decides to use a tool, it returns a response with `stop_reason: "tool_use"` containing one or more `tool_use` content blocks, each with an `id`, `name`, and `input` object. Your application executes the tool, then sends back a `user` message containing `tool_result` blocks keyed by `tool_use_id`. **Critical formatting rule**: `tool_result` blocks in a user message must come before any text content, and they must immediately follow the assistant message that contained the corresponding `tool_use` blocks.

Claude supports `tool_choice` options: `"auto"` (default, Claude decides), `"any"` (must use a tool), `{"type": "tool", "name": "specific_tool"}` (force a specific tool), and `"none"` (prevent tool use). Parallel tool calls are enabled by default — Claude can request multiple tools in a single response.

---

## 2. The agentic loop: two implementation patterns

The agentic loop is the heartbeat of the system: send a message → receive `tool_use` → execute tools locally → send `tool_result` → repeat until the model produces a final text response. There are two patterns worth implementing.

### Pattern A: Manual loop with full control (recommended for this project)

This gives you visibility into every step, enabling logging, user confirmation, streaming display, and custom error handling:

```csharp
public class AgentLoop
{
    private readonly AnthropicClient _client;
    private readonly IToolRegistry _tools;
    private readonly List<Message> _messages = [];

    public async IAsyncEnumerable<AgentEvent> RunAsync(
        string userPrompt, string systemPrompt,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        _messages.Add(new Message(RoleType.User, userPrompt));

        while (true)
        {
            var parameters = new MessageParameters
            {
                Messages = _messages,
                SystemMessage = systemPrompt,
                MaxTokens = 8192,
                Model = AnthropicModels.Claude4Sonnet,
                Tools = _tools.GetToolDefinitions(),
                Stream = true
            };

            // Stream the response for real-time token display
            var fullResponse = new MessageResponse();
            await foreach (var chunk in _client.Messages
                .StreamClaudeMessageAsync(parameters).WithCancellation(ct))
            {
                if (chunk.Delta?.Text is { } text)
                    yield return new TextDelta(text);
                fullResponse = chunk; // accumulate
            }

            _messages.Add(fullResponse.Message);

            if (fullResponse.StopReason != "tool_use")
            {
                yield return new FinalResponse(fullResponse);
                break;
            }

            // Execute each tool call
            var toolResults = new List<ContentBase>();
            foreach (var toolUse in fullResponse.Content.OfType<ToolUseContent>())
            {
                yield return new ToolCallStarted(toolUse.Name, toolUse.Input);
                
                try
                {
                    var result = await _tools.ExecuteAsync(
                        toolUse.Name, toolUse.Input, ct);
                    toolResults.Add(new ToolResultContent
                    {
                        ToolUseId = toolUse.Id,
                        Content = result
                    });
                    yield return new ToolCallCompleted(toolUse.Name, result);
                }
                catch (Exception ex)
                {
                    toolResults.Add(new ToolResultContent
                    {
                        ToolUseId = toolUse.Id,
                        Content = ex.Message,
                        IsError = true
                    });
                    yield return new ToolCallFailed(toolUse.Name, ex);
                }
            }

            _messages.Add(new Message(RoleType.User, toolResults));
        }
    }
}
```

### Pattern B: IChatClient with automatic function invocation

For simpler scenarios or rapid prototyping, `Anthropic.SDK`'s `IChatClient` with `UseFunctionInvocation()` handles the entire loop automatically:

```csharp
IChatClient client = new AnthropicClient().Messages
    .AsBuilder()
    .UseFunctionInvocation() // auto-handles tool loop
    .Build();

ChatOptions options = new()
{
    ModelId = AnthropicModels.Claude4Sonnet,
    MaxOutputTokens = 8192,
    Tools = [
        AIFunctionFactory.Create(
            (string path) => File.ReadAllText(path),
            "read_file", "Read the contents of a file at the given path"),
        AIFunctionFactory.Create(
            (string command) => ExecuteShellCommand(command),
            "run_command", "Execute a shell command and return output"),
    ]
};

var response = await client.GetResponseAsync("Analyze the codebase", options);
```

**Use Pattern A** for the production system — you need human-in-the-loop confirmations, audit logging, streaming display, and fine-grained control over tool execution. Pattern B is useful for testing individual tools quickly.

---

## 3. Tool system: interfaces, registration, and JSON schema generation

Define a clean tool abstraction that maps directly to Claude's tool format:

```csharp
public interface ITool
{
    string Name { get; }
    string Description { get; }
    JsonElement InputSchema { get; }
    Task<string> ExecuteAsync(JsonElement input, CancellationToken ct);
}

public abstract class ToolBase : ITool
{
    public abstract string Name { get; }
    public abstract string Description { get; }
    public abstract JsonElement InputSchema { get; }
    public abstract Task<string> ExecuteAsync(JsonElement input, CancellationToken ct);
    
    // Helper: build JSON Schema from a C# type using System.Text.Json
    protected static JsonElement BuildSchema(params (string name, string type, 
        string desc, bool required)[] properties)
    {
        var props = new Dictionary<string, object>();
        var required = new List<string>();
        
        foreach (var (name, type, desc, req) in properties)
        {
            props[name] = new { type, description = desc };
            if (req) required.Add(name);
        }
        
        return JsonSerializer.SerializeToElement(new
        {
            type = "object",
            properties = props,
            required
        });
    }
}
```

A concrete tool implementation:

```csharp
public class ReadFileTool : ToolBase
{
    private readonly SafeFileOperations _fileOps;

    public ReadFileTool(SafeFileOperations fileOps) => _fileOps = fileOps;

    public override string Name => "read_file";
    public override string Description => 
        "Read the full contents of a file at the specified path. " +
        "Returns the file text. Use this to examine source code, configs, or docs.";
    public override JsonElement InputSchema => BuildSchema(
        ("path", "string", "Relative file path to read", true));

    public override async Task<string> ExecuteAsync(JsonElement input, CancellationToken ct)
    {
        var path = input.GetProperty("path").GetString()!;
        var safePath = _fileOps.ValidatePath(path);
        return await File.ReadAllTextAsync(safePath, ct);
    }
}
```

The tool registry collects tools and serializes their definitions for the API:

```csharp
public class ToolRegistry : IToolRegistry
{
    private readonly Dictionary<string, ITool> _tools = new(StringComparer.OrdinalIgnoreCase);

    public void Register(ITool tool) => _tools[tool.Name] = tool;

    public List<Tool> GetToolDefinitions() =>
        _tools.Values.Select(t => new Tool
        {
            Name = t.Name,
            Description = t.Description,
            InputSchema = t.InputSchema
        }).ToList();

    public async Task<string> ExecuteAsync(
        string name, JsonElement input, CancellationToken ct)
    {
        if (!_tools.TryGetValue(name, out var tool))
            throw new InvalidOperationException($"Unknown tool: {name}");
        return await tool.ExecuteAsync(input, ct);
    }
}
```

Built-in tools to implement: `read_file`, `write_file`, `edit_file` (line-range replacement), `list_files` (glob patterns), `search_files` (grep), `run_command` (shell execution), `web_search`, `web_fetch`, `memory_search`, and `memory_store`.

---

## 4. Persistent memory: hybrid search with SQLite

The memory system combines **SQLite FTS5** for keyword search and **sqlite-vec** (or a pure C# HNSW index) for vector similarity, fused with **Reciprocal Rank Fusion**. This runs entirely locally with zero external dependencies.

### Embedding generation with local ONNX models

Use `Microsoft.SemanticKernel.Connectors.Onnx` with the `bge-micro-v2` model (**22.9 MB**, 384 dimensions, sub-millisecond inference):

```csharp
#pragma warning disable SKEXP0070
var embeddingService = new BertOnnxTextEmbeddingGenerationService(
    onnxModelPath: "models/bge-micro-v2/model.onnx",
    vocabPath: "models/bge-micro-v2/vocab.txt");

ReadOnlyMemory<float> embedding = 
    (await embeddingService.GenerateEmbeddingsAsync(["search query"]))[0];
```

Alternatively, `SmartComponents.LocalEmbeddings` provides an even simpler API with built-in quantization (int8 at 4× compression, binary at 32×):

```csharp
using var embedder = new LocalEmbedder();
var query = embedder.Embed("search query");
var closest = LocalEmbedder.FindClosest(query, candidateEmbeddings, maxResults: 5);
```

### SQLite FTS5 for keyword search

FTS5 is compiled into the default `Microsoft.Data.Sqlite` bundle — no extra extensions needed:

```csharp
// Create content table and FTS5 index
connection.Execute(@"
    CREATE TABLE IF NOT EXISTS memory_chunks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        source TEXT NOT NULL,
        chunk_index INTEGER,
        created_at TEXT DEFAULT (datetime('now')),
        embedding BLOB
    );
    CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
        content, source,
        content='memory_chunks', content_rowid='id',
        tokenize='porter unicode61'
    );");
```

### Hybrid search with Reciprocal Rank Fusion

The industry standard (used by Azure AI Search, Elasticsearch, Weaviate) combines ranked lists from both search methods. **RRF score = Σ 1/(k + rank)** where k=60:

```csharp
public async Task<List<MemoryResult>> HybridSearchAsync(string query, int topK = 10)
{
    var queryEmbedding = await _embedder.GenerateEmbeddingAsync(query);
    
    // Run both searches in parallel
    var keywordTask = KeywordSearchAsync(query, limit: 50);
    var vectorTask = VectorSearchAsync(queryEmbedding, limit: 50);
    await Task.WhenAll(keywordTask, vectorTask);

    // Reciprocal Rank Fusion (k=60)
    const int k = 60;
    var scores = new Dictionary<long, (double Score, MemoryResult Result)>();
    
    int rank = 1;
    foreach (var r in keywordTask.Result)
    {
        scores[r.Id] = (1.0 / (k + rank), r);
        rank++;
    }

    rank = 1;
    foreach (var r in vectorTask.Result)
    {
        double rrfScore = 1.0 / (k + rank);
        scores[r.Id] = scores.TryGetValue(r.Id, out var existing)
            ? (existing.Score + rrfScore, r)
            : (rrfScore, r);
        rank++;
    }

    return scores.Values
        .OrderByDescending(x => x.Score)
        .Take(topK)
        .Select(x => x.Result)
        .ToList();
}
```

### File-based memory layer

Alongside the search index, maintain two plain-text memory stores matching the OpenClaw pattern:

- **Daily Markdown logs** (`~/.agent/logs/2026-02-10.md`): Append-only files capturing every session interaction with timestamps. Chunk and index these for retrieval.
- **MEMORY.md** (`~/.agent/MEMORY.md`): A curated file of persistent facts, preferences, and project context. Updated by a dedicated `memory_store` tool that the agent calls when it learns something worth remembering. Use atomic writes (write to temp file → `File.Move` with overwrite) to prevent corruption.

### Key NuGet packages for memory

```xml
<PackageReference Include="Microsoft.Data.Sqlite" Version="9.0.0" />
<PackageReference Include="Microsoft.SemanticKernel.Connectors.Onnx" Version="1.45.0-alpha" />
<PackageReference Include="Microsoft.Extensions.VectorData.Abstractions" Version="9.7.0" />
<!-- OR for simplicity: -->
<PackageReference Include="SmartComponents.LocalEmbeddings" Version="0.1.0-preview10148" />
```

For the vector storage layer, you have three options: `Microsoft.SemanticKernel.Connectors.SqliteVec` (SQLite-native, uses the `sqlite-vec` extension, **best for persistence**), a pure C# HNSW library like `HnswLite` (with SQLite backing), or the SK in-memory connector for development. Build against `Microsoft.Extensions.VectorData.Abstractions` so you can swap providers later.

---

## 5. System prompt construction and context window management

Dynamically assemble the system prompt from multiple sources, following the pattern used by Claude Code (which has **40+ prompt fragments** conditionally assembled):

```csharp
public class SystemPromptBuilder
{
    public async Task<string> BuildAsync(SessionContext session)
    {
        var sb = new StringBuilder();
        
        // Layer 1: Core identity and behavioral instructions
        sb.AppendLine(await File.ReadAllTextAsync("prompts/AGENTS.md"));
        
        // Layer 2: Tool descriptions (auto-generated from registry)
        sb.AppendLine("\n## Available Tools\n");
        foreach (var tool in _toolRegistry.GetAll())
            sb.AppendLine($"- **{tool.Name}**: {tool.Description}");
        
        // Layer 3: Skill metadata (progressive disclosure — name + description only)
        sb.AppendLine("\n## Available Skills\n");
        foreach (var skill in _skillRegistry.GetMetadata())
            sb.AppendLine($"- **{skill.Name}**: {skill.Description}");
        
        // Layer 4: Memory context
        sb.AppendLine("\n## Memory\n");
        if (File.Exists("MEMORY.md"))
            sb.AppendLine(await File.ReadAllTextAsync("MEMORY.md"));

        // Layer 5: Relevant memories from hybrid search
        var recentQuery = session.LastUserMessage;
        if (recentQuery != null)
        {
            var memories = await _memorySearch.HybridSearchAsync(recentQuery, topK: 5);
            if (memories.Count > 0)
            {
                sb.AppendLine("\n## Relevant Past Context\n");
                foreach (var m in memories)
                    sb.AppendLine($"[{m.Source}, {m.CreatedAt:d}]: {m.Content}\n");
            }
        }

        return sb.ToString();
    }
}
```

### Token counting and compaction

**There is no official offline tokenizer for Claude.** Anthropic provides a free token counting API endpoint at `POST /v1/messages/count_tokens` — use it for accurate counts. For local estimation without an API call, a rough heuristic of **1 token ≈ 4 characters** with a **20% safety buffer** works for English text. The API response also includes `usage.input_tokens` after each call, so track it incrementally.

**Compaction strategy**: When `usage.input_tokens` exceeds **80% of the context window** (e.g., 160K of 200K), trigger summarization. Use a cheaper model (Claude Haiku 4.5) to generate a conversation summary, then replace the full history with the summary plus the last 3-5 message pairs. Anthropic also now offers **server-side compaction** (beta feature `compact_20260112`) that handles this automatically, but client-side gives you more control:

```csharp
public async Task<List<Message>> CompactIfNeededAsync(List<Message> messages)
{
    int tokenCount = await CountTokensAsync(messages);
    int maxTokens = 200_000; // Claude's standard context window
    
    if (tokenCount < (int)(maxTokens * 0.80))
        return messages;

    // Summarize using a cheaper model
    var summaryPrompt = "Summarize the key points, decisions, and context " +
                        "from this conversation. Preserve all technical details, " +
                        "file paths, and action items.";
    var summary = await _client.SummarizeAsync(messages, summaryPrompt,
        model: "claude-haiku-4-5-20250929");

    // Keep summary + last N messages
    var compacted = new List<Message>
    {
        new(RoleType.User, $"[Previous conversation summary]\n{summary}"),
        new(RoleType.Assistant, "Understood. I have the context from our previous discussion.")
    };
    compacted.AddRange(messages.TakeLast(6)); // keep last 3 pairs
    return compacted;
}
```

---

## 6. Session management with JSONL persistence

Follow Claude Code's storage pattern: each session is a UUID-named JSONL file under a project-specific directory:

```
~/.agent/
├── config.json                           # Global settings
├── MEMORY.md                             # Curated persistent memory
├── logs/
│   └── 2026-02-10.md                     # Daily log
├── sessions/
│   └── -Users-dev-myproject/             # Path-encoded project dir
│       ├── {session-id}.jsonl            # Primary session
│       └── {session-id}.meta.json        # Session metadata
└── skills/                               # User-installed skills
```

The JSONL format uses one JSON object per line, written immediately on each event:

```csharp
public class SessionStore
{
    private readonly string _sessionPath;
    private readonly JsonSerializerOptions _jsonOpts = new() { WriteIndented = false };

    public SessionStore(string projectPath, Guid? sessionId = null)
    {
        var encoded = projectPath.Replace(Path.DirectorySeparatorChar, '-')
                                  .Replace(':', '-').TrimStart('-');
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".agent", "sessions", encoded);
        Directory.CreateDirectory(dir);
        
        var id = sessionId ?? Guid.NewGuid();
        _sessionPath = Path.Combine(dir, $"{id}.jsonl");
    }

    public async Task AppendAsync(SessionEvent evt)
    {
        var json = JsonSerializer.Serialize(evt, _jsonOpts);
        await File.AppendAllTextAsync(_sessionPath, json + "\n");
    }

    public async IAsyncEnumerable<SessionEvent> LoadAsync()
    {
        if (!File.Exists(_sessionPath)) yield break;
        await foreach (var line in File.ReadLinesAsync(_sessionPath))
        {
            if (!string.IsNullOrWhiteSpace(line))
                yield return JsonSerializer.Deserialize<SessionEvent>(line)!;
        }
    }

    public async Task<List<Message>> ReconstructMessagesAsync()
    {
        var messages = new List<Message>();
        await foreach (var evt in LoadAsync())
        {
            if (evt.Type is "user" or "assistant")
                messages.Add(evt.ToMessage());
        }
        return messages;
    }
}

public record SessionEvent(
    string Type,         // "user" | "assistant" | "tool_use" | "tool_result" | "system"
    string Role,
    object Content,
    DateTime Timestamp,
    string? ToolName = null,
    string? ToolUseId = null,
    bool IsMeta = false  // Hidden from UI but sent to API
);
```

For the **serial queue pattern**, use a `SemaphoreSlim(1, 1)` per session to ensure only one agent turn executes at a time:

```csharp
private readonly SemaphoreSlim _turnLock = new(1, 1);

public async Task<AgentResponse> ProcessAsync(string input, CancellationToken ct)
{
    await _turnLock.WaitAsync(ct);
    try { return await RunAgentLoopAsync(input, ct); }
    finally { _turnLock.Release(); }
}
```

---

## 7. Skills and plugin system: Markdown-first with compiled extensions

OpenClaw and Claude Code both use **Markdown skill files** with YAML frontmatter as the primary skill format. This is the right approach — skills are prompt templates that modify the agent's behavior, not compiled code. Compiled plugins are a separate concern for tools that need executable logic.

### Markdown skills (SKILL.md format)

```yaml
---
name: code-reviewer
description: Reviews code changes for bugs, style issues, and best practices
allowed-tools: read_file,search_files,list_files
model: claude-sonnet-4-5-20250929
version: 1.0.0
---

# Code Review Skill

## Instructions
1. Read the files specified by the user
2. Analyze for: correctness, performance, security, readability
3. Provide specific line-by-line feedback
4. Suggest concrete improvements with code examples

## Output Format
Use markdown with headers for each file reviewed...
```

### Skill loader with progressive disclosure

Only load name + description at startup; load full content on demand:

```csharp
public class SkillRegistry
{
    private readonly Dictionary<string, SkillMetadata> _metadata = [];
    private readonly string _skillsDirectory;

    public void LoadMetadataFromDirectory(string directory)
    {
        foreach (var file in Directory.GetFiles(directory, "SKILL.md", 
            SearchOption.AllDirectories))
        {
            var content = File.ReadAllText(file);
            var frontmatter = ParseYamlFrontmatter(content);
            _metadata[frontmatter.Name] = new SkillMetadata(
                frontmatter.Name,
                frontmatter.Description,
                file,
                frontmatter.AllowedTools?.Split(',') ?? []);
        }
    }

    // Level 1: Just metadata for system prompt
    public IEnumerable<SkillMetadata> GetMetadata() => _metadata.Values;

    // Level 2: Full content loaded when agent invokes the skill
    public async Task<string> LoadFullContentAsync(string name)
    {
        if (!_metadata.TryGetValue(name, out var meta))
            throw new KeyNotFoundException($"Skill not found: {name}");
        return await File.ReadAllTextAsync(meta.FilePath);
    }
}
```

Use `YamlDotNet` (NuGet) to parse the YAML frontmatter. For compiled C# tool plugins that need to be loaded dynamically, use `AssemblyLoadContext` with `isCollectible: true` for hot-reload support, combined with a shared `ITool` interface from the Core project.

---

## 8. Console UI: Spectre.Console with a hybrid streaming approach

**Spectre.Console** (v0.54.0, 32.3M downloads, MIT, .NET Foundation) is the clear choice. It provides rich markup, tables, panels, spinners, prompts, and `LiveDisplay` for in-place content updates. Terminal.Gui is overkill for a chat-style interface.

The key challenge is **streaming token display**. Use a hybrid strategy: show a spinner while waiting for the first token, stream raw text during generation, then re-render with full Markdown formatting after completion:

```csharp
public class ConsoleUI
{
    public async Task DisplayStreamingResponseAsync(IAsyncEnumerable<AgentEvent> events)
    {
        var fullText = new StringBuilder();
        bool firstToken = true;

        await foreach (var evt in events)
        {
            switch (evt)
            {
                case TextDelta delta:
                    if (firstToken)
                    {
                        AnsiConsole.WriteLine();
                        firstToken = false;
                    }
                    Console.Write(delta.Text); // Raw write for streaming speed
                    fullText.Append(delta.Text);
                    break;

                case ToolCallStarted tool:
                    AnsiConsole.MarkupLine(
                        $"\n[dim]⚙ Calling [bold]{tool.Name}[/]...[/]");
                    break;

                case ToolCallCompleted tool:
                    AnsiConsole.MarkupLine(
                        $"[green]  ✓ {tool.Name} complete[/]");
                    break;

                case ToolCallFailed tool:
                    AnsiConsole.MarkupLine(
                        $"[red]  ✗ {tool.Name} failed: {tool.Error.Message}[/]");
                    break;

                case FinalResponse _:
                    Console.WriteLine("\n");
                    // Re-render with Markdown formatting
                    RenderMarkdown(fullText.ToString());
                    break;
            }
        }
    }

    private void RenderMarkdown(string markdown)
    {
        // Use Markdig to parse, then custom renderer for Spectre markup
        // Headers → [bold blue], code → Panel with dim background, etc.
        var panel = new Panel(new Markup(Markup.Escape(markdown)))
            .Border(BoxBorder.Rounded)
            .Header("[green]Claude[/]");
        AnsiConsole.Write(panel);
    }

    public string GetUserInput()
    {
        return AnsiConsole.Prompt(
            new TextPrompt<string>("[blue]>[/]")
                .AllowEmpty());
    }
}
```

For Markdown-to-console rendering, use **Markdig** (v0.44.0, 100M+ downloads) to parse the Markdown AST, then walk it to emit Spectre.Console markup: headers become `[bold blue]`, code blocks become `Panel` widgets, bold text maps to `[bold]`, and links use Spectre's `[link=url]` syntax.

---

## 9. Recommended project structure

```
ClaudeAgent.sln
├── src/
│   ├── ClaudeAgent.Core/              # Shared interfaces and models
│   │   ├── Interfaces/
│   │   │   ├── ITool.cs               # Tool abstraction
│   │   │   ├── IToolRegistry.cs
│   │   │   ├── ISkillRegistry.cs
│   │   │   ├── IMemoryService.cs
│   │   │   └── ISessionStore.cs
│   │   ├── Models/
│   │   │   ├── AgentEvent.cs          # Event hierarchy (TextDelta, ToolCall, etc.)
│   │   │   ├── SessionEvent.cs
│   │   │   └── MemoryResult.cs
│   │   └── Services/
│   │       ├── AgentLoop.cs           # The core agentic loop
│   │       ├── SystemPromptBuilder.cs
│   │       └── ContextCompactor.cs
│   │
│   ├── ClaudeAgent.AI/                # Claude API integration
│   │   ├── ClaudeProvider.cs          # Wraps Anthropic.SDK
│   │   ├── StreamingHandler.cs
│   │   ├── TokenCounter.cs
│   │   └── ServiceExtensions.cs       # AddClaudeAI(config) DI extension
│   │
│   ├── ClaudeAgent.Tools/             # Built-in tool implementations
│   │   ├── FileSystem/
│   │   │   ├── ReadFileTool.cs
│   │   │   ├── WriteFileTool.cs
│   │   │   ├── ListFilesTool.cs
│   │   │   └── SearchFilesTool.cs
│   │   ├── Shell/
│   │   │   ├── RunCommandTool.cs
│   │   │   └── SafeProcessExecutor.cs
│   │   ├── Web/
│   │   │   ├── WebSearchTool.cs
│   │   │   └── WebFetchTool.cs
│   │   ├── ToolRegistry.cs
│   │   ├── CommandPolicy.cs           # Allowlist/blocklist
│   │   └── ServiceExtensions.cs
│   │
│   ├── ClaudeAgent.Memory/            # Persistent memory system
│   │   ├── HybridSearchService.cs     # RRF fusion of FTS5 + vector
│   │   ├── SqliteMemoryStore.cs       # FTS5 + sqlite-vec
│   │   ├── EmbeddingService.cs        # Local ONNX embeddings
│   │   ├── DailyLogService.cs
│   │   ├── MemoryFileService.cs       # MEMORY.md management
│   │   ├── TextChunker.cs
│   │   └── ServiceExtensions.cs
│   │
│   ├── ClaudeAgent.Skills/            # Skill/plugin system
│   │   ├── SkillRegistry.cs
│   │   ├── SkillLoader.cs             # YAML frontmatter parser
│   │   ├── PluginLoader.cs            # AssemblyLoadContext for compiled plugins
│   │   └── ServiceExtensions.cs
│   │
│   └── ClaudeAgent.Console/           # Entry point
│       ├── Program.cs                 # Host builder, DI composition root
│       ├── UI/
│       │   ├── ConsoleUI.cs
│       │   ├── MarkdownRenderer.cs
│       │   └── SetupWizard.cs         # First-run API key configuration
│       ├── appsettings.json
│       └── prompts/
│           └── AGENTS.md              # Base system prompt
│
├── skills/                            # User-created skills
│   └── code-reviewer/SKILL.md
│
├── tests/
│   ├── ClaudeAgent.Core.Tests/
│   ├── ClaudeAgent.Tools.Tests/
│   └── ClaudeAgent.Memory.Tests/
│
├── Directory.Build.props
├── Directory.Packages.props           # Central package management
└── .editorconfig
```

### Program.cs composition root

```csharp
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

builder.Configuration.AddUserSecrets<Program>();

builder.Services
    .AddSingleton<IAnsiConsole>(AnsiConsole.Console)
    .AddClaudeAI(builder.Configuration)
    .AddAgentTools(options =>
    {
        options.WorkingDirectory = Environment.CurrentDirectory;
        options.CommandTimeoutSeconds = 30;
        options.RequireApprovalForWrites = true;
    })
    .AddMemory(options =>
    {
        options.DatabasePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".agent", "memory.db");
        options.EmbeddingModelPath = "models/bge-micro-v2/model.onnx";
    })
    .AddSkills(options =>
    {
        options.SkillDirectories = ["./skills", "~/.agent/skills"];
    })
    .AddSingleton<AgentLoop>()
    .AddSingleton<ConsoleUI>()
    .AddSingleton<SessionStore>();

var host = builder.Build();
var ui = host.Services.GetRequiredService<ConsoleUI>();
var agent = host.Services.GetRequiredService<AgentLoop>();

// Main interaction loop
AnsiConsole.Write(new FigletText("Claude Agent").Color(Color.Blue));
while (true)
{
    var input = ui.GetUserInput();
    if (input is "/exit" or "/quit") break;
    if (input is "/compact") { await agent.CompactAsync(); continue; }
    
    await ui.DisplayStreamingResponseAsync(
        agent.RunAsync(input, CancellationToken.None));
}
```

---

## 10. Security hardening for tool execution on Windows

Security is non-negotiable when an LLM can execute shell commands. Implement **defense in depth** across five layers.

### API key storage: Windows Credential Manager

Use the `Meziantou.Framework.Win32.CredentialManager` package (v1.7.11) for encrypted-at-rest storage backed by DPAPI. This is **significantly more secure** than .NET User Secrets (which stores unencrypted JSON):

```csharp
// First-run setup
CredentialManager.WriteCredential(
    applicationName: "ClaudeAgent_ApiKey",
    userName: "anthropic",
    secret: apiKey,
    persistence: CredentialPersistence.LocalMachine);

// Runtime retrieval
var cred = CredentialManager.ReadCredential("ClaudeAgent_ApiKey");
string apiKey = cred?.Password 
    ?? throw new InvalidOperationException("Run setup first.");
```

### Process sandboxing with Windows Job Objects

Use `Meziantou.Framework.Win32.Jobs` to constrain spawned processes with CPU, memory, and network limits. Use `CliWrap` (by Tyrrrz) for safe async process execution with automatic deadlock prevention and `CancellationToken` support:

```csharp
var result = await Cli.Wrap("git")
    .WithArguments(["status"])
    .WithWorkingDirectory(projectRoot)
    .WithValidation(CommandResultValidation.None)
    .ExecuteBufferedAsync(
        new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token);
```

### Command allowlisting

Maintain explicit allowlists (`git`, `dotnet`, `node`, `npm`, `python`, `cat`, `find`, `grep`) and blocklists (`powershell`, `reg`, `netsh`, `certutil`, `format`, `diskpart`, `rundll32`). Also block dangerous argument patterns: pipes (`|`), redirects (`>`), command chaining (`&&`, `||`), and backtick execution. **Any command not on the allowlist requires explicit user confirmation.**

### Path validation for file operations

Always canonicalize with `Path.GetFullPath()` and verify the result starts with the allowed root directory. Block access to `C:\Windows`, `C:\Program Files`, `AppData`, and sensitive filenames (`.env`, `id_rsa`, `secrets.json`).

### Prompt injection defense

When feeding file contents or web pages to the model, wrap them in clearly labeled XML tags (`<untrusted_file_content>`) with explicit instructions in the system prompt to treat them as data only. Implement pattern detection for known injection phrases ("ignore previous instructions", "you are now", etc.) and flag suspicious content for user review. **Most importantly, implement human-in-the-loop approval** for all write operations and command execution — classify actions by risk level and require confirmation for anything above "low."

---

## Complete NuGet dependency map

| Package | Purpose | Version |
|---|---|---|
| `Anthropic.SDK` | Claude API client | 5.9.0 |
| `Microsoft.Extensions.AI` | Provider-agnostic AI abstraction | latest preview |
| `Microsoft.Extensions.Hosting` | DI, configuration, logging | 8.0.x |
| `Spectre.Console` | Rich console UI | 0.54.0 |
| `Markdig` | Markdown parsing | 0.44.0 |
| `Microsoft.Data.Sqlite` | SQLite + FTS5 | 9.0.0 |
| `Microsoft.SemanticKernel.Connectors.Onnx` | Local ONNX embeddings | 1.45.0-alpha |
| `Microsoft.Extensions.VectorData.Abstractions` | Vector store abstraction | 9.7.0 |
| `YamlDotNet` | YAML frontmatter parsing | latest |
| `CliWrap` | Safe process execution | latest |
| `Meziantou.Framework.Win32.CredentialManager` | Encrypted API key storage | 1.7.11 |
| `Meziantou.Framework.Win32.Jobs` | Process sandboxing | 3.4.10 |
| `Serilog` + `Serilog.Sinks.File` | Structured audit logging | latest |
| `System.Net.ServerSentEvents` | SSE parsing (if using raw HTTP) | 10.0.0 |

---

## Conclusion: what makes this architecture work

The design centers on three principles that separate a production agent from a toy: **the agentic loop must be transparent** (Pattern A with explicit tool execution, audit logging, and human confirmation), **memory must be hybrid** (keyword search catches exact terms that vector search misses, and vice versa — RRF fusion gives you both), and **security must be layered** (no single defense is sufficient when an LLM controls tool execution).

The biggest architectural insight from studying OpenClaw and Claude Code is **progressive disclosure for skills** — loading only names and descriptions at startup keeps the system prompt lean, while full skill content loads on demand when the agent decides to use one. This is how you scale to hundreds of skills without blowing the context window.

Start by implementing the agentic loop with `ReadFile`, `WriteFile`, and `RunCommand` tools. Get the streaming console display working. Then layer in memory (SQLite FTS5 first — it's simpler and covers 80% of search needs), then vector search, then skills. The project structure supports this incremental approach because each concern lives in its own project with clean DI boundaries.