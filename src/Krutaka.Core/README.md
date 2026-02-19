# Krutaka.Core

## Purpose

Krutaka.Core is the zero-dependency foundation of the Krutaka agent platform. It defines every interface, model, record, enum, and base class that all other projects depend on. No business logic is implemented here — only contracts, data carriers, and the core orchestration engine (`AgentOrchestrator`) that drives the agentic loop.

## Dependencies

- **NuGet packages:** None — this project has zero NuGet dependencies by design.
- **Project references:** None — `Krutaka.Core` must never reference any other Krutaka project.

## Responsibilities

- Define all interfaces consumed by `Krutaka.Tools`, `Krutaka.AI`, `Krutaka.Memory`, `Krutaka.Skills`, `Krutaka.Console`, and `Krutaka.Telegram`
- Provide all shared data models (records, enums, DTOs) used across the solution
- Implement `AgentOrchestrator` — the central agentic loop that drives tool selection and execution
- Implement `ContextCompactor` — manages conversation context size and pre-compaction memory flush
- Implement `SystemPromptBuilder` — assembles the layered system prompt sent to Claude
- Implement `ManagedSession` and `CommandApprovalCache` — per-session state containers
- Implement `CorrelationContext` and `CorrelationContextAccessor` — request correlation across async call chains
- Define security exception types used to signal access and approval violations

## Directory Layout

| Directory | Description | Key Files |
|---|---|---|
| `Abstractions/` | All service interfaces | `ITool.cs`, `IClaudeClient.cs`, `IAuditLogger.cs`, `IAccessPolicyEngine.cs`, `ISessionFactory.cs`, `ISessionManager.cs`, `ISessionStore.cs`, `ISessionAccessStore.cs`, `ICommandPolicy.cs`, `ICommandRiskClassifier.cs`, `ICommandApprovalCache.cs`, `IFileOperations.cs`, `IMemoryService.cs`, `ISecretsProvider.cs`, `ISecurityPolicy.cs`, `ISkillRegistry.cs`, `IToolOptions.cs`, `IToolRegistry.cs` |
| `Models/` | Records, enums, and DTOs | `AgentEvent.cs`, `AccessDecision.cs`, `AccessLevel.cs`, `CommandDecision.cs`, `CommandExecutionRequest.cs`, `CommandOutcome.cs`, `CommandRiskRule.cs`, `CommandRiskTier.cs`, `DirectoryAccessRequest.cs`, `EvictionStrategy.cs`, `HostMode.cs`, `MemoryResult.cs`, `SessionAccessGrant.cs`, `SessionBudget.cs`, `SessionEvent.cs`, `SessionInfo.cs`, `SessionManagerOptions.cs`, `SessionRequest.cs`, `SessionState.cs`, `SessionSummary.cs`, `SuspendedSessionInfo.cs`, `AuditEvent.cs`, `AgentConfiguration.cs`, `TelegramSecurityConfig.cs`, `TelegramConfigValidator.cs`, `TelegramTransportMode.cs`, `TelegramUserConfig.cs`, `TelegramUserRole.cs` |
| `Orchestration/` | Agentic loop and context management | `AgentOrchestrator.cs`, `ContextCompactor.cs` |
| `Prompt/` | System prompt construction | `SystemPromptBuilder.cs` |
| `Session/` | Per-session state | `ManagedSession.cs`, `CommandApprovalCache.cs` |
| `Correlation/` | Request correlation across async chains | `CorrelationContext.cs`, `CorrelationContextAccessor.cs`, `ICorrelationContextAccessor.cs` |
| `Security/` | Security exception types | `CommandApprovalRequiredException.cs`, `DirectoryAccessRequiredException.cs` |
| *(root)* | Project root files | `ToolBase.cs`, `AssemblyInfo.cs`, `Krutaka.Core.csproj`, `packages.lock.json` |

## Used By

All other Krutaka projects depend on `Krutaka.Core`:

- `Krutaka.AI` — consumes `IClaudeClient`, `AgentConfiguration`
- `Krutaka.Tools` — consumes `ITool`, `IToolRegistry`, `IAccessPolicyEngine`, `ICommandPolicy`, `ICommandRiskClassifier`, `ISecurityPolicy`, `ISessionFactory`, `ISessionManager`
- `Krutaka.Memory` — consumes `IMemoryService`, `ISessionStore`, `IFileOperations`
- `Krutaka.Skills` — consumes `ISkillRegistry`, `ITool`
- `Krutaka.Console` — composition root; references all projects
- `Krutaka.Telegram` — composition root; references all projects

## Notes

> ⚠️ **Security-critical project.** This project contains all security-critical interfaces including `IAccessPolicyEngine`, `ICommandPolicy`, `ISecurityPolicy`, and `ISessionAccessStore`. Any changes to these interfaces require careful review and must be backwards-compatible or coordinated across all implementing projects.
