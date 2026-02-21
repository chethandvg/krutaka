using Krutaka.AI;
using Krutaka.Core;
using Krutaka.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;

namespace Krutaka.Console;

/// <summary>
/// Static helper methods for console session setup, extracted from Program.cs to reduce file length.
/// </summary>
internal static class ConsoleSessionHelpers
{
    /// <summary>
    /// Creates a memory writer delegate for pre-compaction flush, if the service is configured.
    /// </summary>
    internal static Func<string, CancellationToken, Task>? CreateMemoryWriter(IServiceProvider serviceProvider)
    {
        var memoryFileService = serviceProvider.GetService<MemoryFileService>();
        var toolOptions = serviceProvider.GetService<IToolOptions>();

        if (memoryFileService != null && toolOptions?.EnablePreCompactionFlush == true)
        {
            return async (content, ct) => await memoryFileService.AppendRawMarkdownAsync(content, ct).ConfigureAwait(false);
        }

        return null;
    }

    /// <summary>
    /// Creates a <see cref="SystemPromptBuilder"/> using the session's tool registry, resolving
    /// the AGENTS.md prompt file from several candidate locations.
    /// </summary>
    internal static SystemPromptBuilder CreateSystemPromptBuilder(
        IToolRegistry toolRegistry,
        string workingDirectory,
        IServiceProvider serviceProvider)
    {
        // Try to locate AGENTS.md in multiple locations
        var agentsPromptPath = Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..", // Navigate to repo root from bin/Debug/net10.0-windows
            "prompts", "AGENTS.md");

        // Normalize the path
        agentsPromptPath = Path.GetFullPath(agentsPromptPath);

        // Fallback 1: Check if running from published location
        if (!File.Exists(agentsPromptPath))
        {
            agentsPromptPath = Path.Combine(AppContext.BaseDirectory, "prompts", "AGENTS.md");
        }

        // Fallback 2: Try current working directory
        if (!File.Exists(agentsPromptPath))
        {
            agentsPromptPath = Path.Combine(workingDirectory, "prompts", "AGENTS.md");
        }

        // Final check - if still not found, log warning and use empty path (will fail at runtime)
        if (!File.Exists(agentsPromptPath))
        {
            Log.Warning("AGENTS.md not found. SystemPromptBuilder may fail at runtime. Searched: {BaseDir}, {WorkingDir}",
                AppContext.BaseDirectory, workingDirectory);
            agentsPromptPath = "prompts/AGENTS.md"; // Let it fail with a clear error
        }

        var skillRegistry = serviceProvider.GetService<ISkillRegistry>();
        var memoryService = serviceProvider.GetService<IMemoryService>();
        var memoryFileService = serviceProvider.GetService<MemoryFileService>();
        var commandRiskClassifier = serviceProvider.GetService<ICommandRiskClassifier>();
        var toolOptions = serviceProvider.GetService<IToolOptions>();
        var promptLogger = serviceProvider.GetService<ILogger<SystemPromptBuilder>>();

        Func<CancellationToken, Task<string>>? memoryFileReader = null;
        if (memoryFileService != null)
        {
            memoryFileReader = async (ct) => await memoryFileService.ReadMemoryAsync(ct).ConfigureAwait(false);
        }

        return new SystemPromptBuilder(
            toolRegistry,
            agentsPromptPath,
            skillRegistry,
            memoryService,
            memoryFileReader,
            commandRiskClassifier,
            toolOptions,
            logger: promptLogger);
    }

    /// <summary>
    /// Extracts the <see cref="IToolRegistry"/> from a session's orchestrator via reflection,
    /// since <see cref="AgentOrchestrator"/> does not expose it directly.
    /// </summary>
    internal static IToolRegistry CreateSessionToolRegistry(ManagedSession session)
    {
        // The SessionFactory creates the tool registry and passes it to the orchestrator.
        // We need to extract it from the orchestrator using reflection.
        var orchestratorType = session.Orchestrator.GetType();
        var toolRegistryField = orchestratorType.GetField(
            "_toolRegistry",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);

        if (toolRegistryField != null)
        {
            var registry = toolRegistryField.GetValue(session.Orchestrator) as IToolRegistry;
            if (registry != null)
            {
                return registry;
            }
        }

        // Fallback: this should never happen, but if reflection fails, throw an error
        throw new InvalidOperationException(
            "Unable to extract tool registry from session. This is a programming error.");
    }
}
