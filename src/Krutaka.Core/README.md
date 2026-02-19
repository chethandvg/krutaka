# Krutaka.Core

## Purpose

`Krutaka.Core` is the zero-dependency foundation of the Krutaka agent system. It defines all shared interfaces, data models, and core business logic that every other project in the solution depends on. No other Krutaka project may reference each other directly — all cross-cutting contracts are expressed here. This project is deliberately kept dependency-free to prevent circular references and to ensure maximum portability.

## Dependencies

- **NuGet packages:** None — this is a zero-dependency project.
- **Project references:** None — `Krutaka.Core` must never reference any other Krutaka project.

## Responsibilities

- Define all service interfaces (`ITool`, `IClaudeClient`, `ISessionManager`, `IAccessPolicyEngine`, etc.)
- Define all shared data models, records, enums, and DTOs
- Implement the core agentic orchestration loop (`AgentOrchestrator`)
- Implement context compaction logic (`ContextCompactor`)
- Implement the system prompt builder (`SystemPromptBuilder`)
- Implement session state management (`ManagedSession`, `CommandApprovalCache`)
- Implement correlation context propagation (`CorrelationContext`, `CorrelationContextAccessor`)
- Define security exception types (`CommandApprovalRequiredException`, `DirectoryAccessRequiredException`)
- Provide the base class for all tools (`ToolBase`)

## Directory Layout

| Directory | Description | Key Files |
|---|---|---|
| `Abstractions/` | All service interface definitions | `ITool.cs`, `IClaudeClient.cs`, `IAuditLogger.cs`, `IAccessPolicyEngine.cs`, `ISessionFactory.cs`, `ISessionManager.cs`, `ISessionStore.cs`, `ISessionAccessStore.cs`, `ICommandPolicy.cs`, `ICommandRiskClassifier.cs`, `ICommandApprovalCache.cs`, `IFileOperations.cs`, `IMemoryService.cs`, `ISecretsProvider.cs`, `ISecurityPolicy.cs`, `ISkillRegistry.cs`, `IToolOptions.cs`, `IToolRegistry.cs` |
| `Models/` | Records, enums, and DTOs shared across projects | `AgentEvent.cs`, `AccessDecision.cs`, `AccessLevel.cs`, `CommandDecision.cs`, `CommandRiskTier.cs`, `HostMode.cs`, `SessionInfo.cs`, `SessionState.cs`, `TelegramSecurityConfig.cs`, `TelegramUserConfig.cs`, `TelegramUserRole.cs`, and more |
| `Orchestration/` | Core agentic loop and context management | `AgentOrchestrator.cs`, `ContextCompactor.cs` |
| `Prompt/` | System prompt construction | `SystemPromptBuilder.cs` |
| `Session/` | Per-session state and approval caching | `ManagedSession.cs`, `CommandApprovalCache.cs` |
| `Correlation/` | Request correlation and context propagation | `CorrelationContext.cs`, `CorrelationContextAccessor.cs`, `ICorrelationContextAccessor.cs` |
| `Security/` | Security-related exception types | `CommandApprovalRequiredException.cs`, `DirectoryAccessRequiredException.cs` |
| *(root)* | Base class and project metadata | `ToolBase.cs`, `AssemblyInfo.cs` |

## Used By

All other projects in the solution depend on `Krutaka.Core`:

- `Krutaka.AI` — uses `IClaudeClient`, `AgentEvent`, and related models
- `Krutaka.Tools` — uses `ITool`, `IAccessPolicyEngine`, `ICommandPolicy`, `ISecurityPolicy`, and all security models
- `Krutaka.Memory` — uses `IMemoryService`, `ISessionStore`, and memory-related models
- `Krutaka.Skills` — uses `ISkillRegistry`, `ITool`, and tool models
- `Krutaka.Console` — composition root; uses all interfaces and models
- `Krutaka.Telegram` — composition root; uses all interfaces and models

## Notes

> ⚠️ **Security-critical project.** This project contains all security-critical interfaces (`IAccessPolicyEngine`, `ICommandPolicy`, `ISecurityPolicy`, `ISessionAccessStore`). Any changes to these interfaces require careful review and must be accompanied by corresponding implementation and test updates in all dependent projects.
