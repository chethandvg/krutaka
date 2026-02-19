# Krutaka.Memory

## Purpose

Provides persistent memory services including SQLite FTS5 keyword search, MEMORY.md file management, JSONL session persistence, daily interaction logging, and text chunking.

## Dependencies

- **NuGet packages:** `Microsoft.Data.Sqlite`, `Microsoft.Extensions.DependencyInjection`
- **Project references:** `Krutaka.Core`

## Responsibilities

- Persist and search long-term memories in a SQLite FTS5 database (`SqliteMemoryStore`)
- Manage the MEMORY.md file used to surface key facts to Claude (`MemoryFileService`)
- Persist and resume conversation sessions as JSONL files (`SessionStore`)
- Write daily interaction logs and flush memories at session close (`DailyLogService`)
- Chunk large text inputs before indexing (`TextChunker`)
- Provide DI registration via `AddMemory()` extension (`ServiceExtensions`)

## Directory Layout

| Directory | Description | Key Files |
|-----------|-------------|-----------|
| `Storage/` | SQLite memory store, MEMORY.md management, text chunking | `SqliteMemoryStore.cs`, `MemoryFileService.cs`, `TextChunker.cs` |
| `Tools/` | Claude tool wrappers for memory store and search | `MemoryStoreTool.cs`, `MemorySearchTool.cs` |
| _(root)_ | Session persistence, daily logging, configuration, DI | `SessionStore.cs`, `DailyLogService.cs`, `MemoryOptions.cs`, `ServiceExtensions.cs` |

## Used By

- `Krutaka.Console` — composition root that calls `AddMemory()` and uses `SessionStore` directly

## Notes

- `SessionStore` is instantiated per-session by `SessionFactory` (in `Krutaka.Tools`), not registered as a singleton.
- `SqliteMemoryStore.InitializeAsync()` is called synchronously during DI registration to ensure the database schema is ready before first use.
