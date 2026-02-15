using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Integration tests for ToolRegistry with actual tool implementations.
/// Verifies that tool definitions serialize correctly to Claude API format.
/// </summary>
public sealed class ToolRegistryIntegrationTests : IDisposable
{
    private readonly string _testRoot;
    private readonly ToolRegistry _registry;
    private static readonly JsonSerializerOptions IndentedJsonOptions = new()
    {
        WriteIndented = true
    };

    private static readonly JsonSerializerOptions SnakeCaseJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true
    };

    public ToolRegistryIntegrationTests()
    {
        // Use CI-safe test directory (avoids LocalAppData which is blocked by security policy)
        _testRoot = TestDirectoryHelper.GetTestDirectory("registry-test");
        Directory.CreateDirectory(_testRoot);

        _registry = new ToolRegistry();
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Should_RegisterAllTools_AndSerializeToValidJSON()
    {
        // Arrange - Register all 6 tools
        var fileOps = new SafeFileOperations(null);
        var securityPolicy = new CommandPolicy(fileOps);
        
        // v0.3.0: Create command policy for RunCommandTool
        var classifier = new CommandRiskClassifier();
        var commandPolicyOptions = new CommandPolicyOptions
        {
            ModerateAutoApproveInTrustedDirs = true,
            TierOverrides = Array.Empty<CommandRiskRule>()
        };
        var commandPolicy = new GraduatedCommandPolicy(classifier, securityPolicy, null, null, commandPolicyOptions);
        
        _registry.Register(new ReadFileTool(_testRoot, fileOps));
        _registry.Register(new WriteFileTool(_testRoot, fileOps));
        _registry.Register(new EditFileTool(_testRoot, fileOps));
        _registry.Register(new ListFilesTool(_testRoot, fileOps));
        _registry.Register(new SearchFilesTool(_testRoot, fileOps));
        _registry.Register(new RunCommandTool(_testRoot, securityPolicy, commandPolicy: commandPolicy));

        // Act
        var definitions = _registry.GetToolDefinitions();
        var json = JsonSerializer.Serialize(definitions, IndentedJsonOptions);

        // Assert
        json.Should().NotBeNullOrWhiteSpace();

        var jsonDoc = JsonDocument.Parse(json);
        jsonDoc.RootElement.ValueKind.Should().Be(JsonValueKind.Array);
        jsonDoc.RootElement.GetArrayLength().Should().Be(6);

        // Verify each tool has required Claude API fields
        foreach (var toolElement in jsonDoc.RootElement.EnumerateArray())
        {
            toolElement.TryGetProperty("name", out var name).Should().BeTrue();
            name.GetString().Should().NotBeNullOrEmpty();

            toolElement.TryGetProperty("description", out var description).Should().BeTrue();
            description.GetString().Should().NotBeNullOrEmpty();
            description.GetString()!.Length.Should().BeGreaterThan(50, "Claude recommends 3-4 sentence descriptions");

            toolElement.TryGetProperty("input_schema", out var inputSchema).Should().BeTrue();
            inputSchema.ValueKind.Should().Be(JsonValueKind.Object);

            // Verify input_schema has required JSON Schema fields
            inputSchema.TryGetProperty("type", out var schemaType).Should().BeTrue();
            schemaType.GetString().Should().Be("object");

            inputSchema.TryGetProperty("properties", out var properties).Should().BeTrue();
            properties.ValueKind.Should().Be(JsonValueKind.Object);
        }
    }

    [Fact]
    public void Should_ContainExpectedToolNames()
    {
        // Arrange - Register all tools
        var fileOps = new SafeFileOperations(null);
        var securityPolicy = new CommandPolicy(fileOps);
        
        // v0.3.0: Create command policy for RunCommandTool
        var classifier = new CommandRiskClassifier();
        var commandPolicyOptions = new CommandPolicyOptions
        {
            ModerateAutoApproveInTrustedDirs = true,
            TierOverrides = Array.Empty<CommandRiskRule>()
        };
        var commandPolicy = new GraduatedCommandPolicy(classifier, securityPolicy, null, null, commandPolicyOptions);
        
        _registry.Register(new ReadFileTool(_testRoot, fileOps));
        _registry.Register(new WriteFileTool(_testRoot, fileOps));
        _registry.Register(new EditFileTool(_testRoot, fileOps));
        _registry.Register(new ListFilesTool(_testRoot, fileOps));
        _registry.Register(new SearchFilesTool(_testRoot, fileOps));
        _registry.Register(new RunCommandTool(_testRoot, securityPolicy, commandPolicy: commandPolicy));

        // Act
        var definitions = _registry.GetToolDefinitions();
        var json = JsonSerializer.Serialize(definitions);
        var jsonDoc = JsonDocument.Parse(json);

        var toolNames = jsonDoc.RootElement
            .EnumerateArray()
            .Select(t => t.GetProperty("name").GetString())
            .ToList();

        // Assert
        toolNames.Should().Contain("read_file");
        toolNames.Should().Contain("write_file");
        toolNames.Should().Contain("edit_file");
        toolNames.Should().Contain("list_files");
        toolNames.Should().Contain("search_files");
        toolNames.Should().Contain("run_command");
    }

    [Fact]
    public void Should_HaveValidInputSchemaForEachTool()
    {
        // Arrange
        var fileOps = new SafeFileOperations(null);
        var securityPolicy = new CommandPolicy(fileOps);
        
        // v0.3.0: Create command policy for RunCommandTool
        var classifier = new CommandRiskClassifier();
        var commandPolicyOptions = new CommandPolicyOptions
        {
            ModerateAutoApproveInTrustedDirs = true,
            TierOverrides = Array.Empty<CommandRiskRule>()
        };
        var commandPolicy = new GraduatedCommandPolicy(classifier, securityPolicy, null, null, commandPolicyOptions);
        
        _registry.Register(new ReadFileTool(_testRoot, fileOps));
        _registry.Register(new WriteFileTool(_testRoot, fileOps));
        _registry.Register(new EditFileTool(_testRoot, fileOps));
        _registry.Register(new ListFilesTool(_testRoot, fileOps));
        _registry.Register(new SearchFilesTool(_testRoot, fileOps));
        _registry.Register(new RunCommandTool(_testRoot, securityPolicy, commandPolicy: commandPolicy));

        // Act
        var definitions = _registry.GetToolDefinitions();
        var json = JsonSerializer.Serialize(definitions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - Verify specific tool schemas
        foreach (var toolElement in jsonDoc.RootElement.EnumerateArray())
        {
            var name = toolElement.GetProperty("name").GetString();
            var inputSchema = toolElement.GetProperty("input_schema");

            switch (name)
            {
                case "read_file":
                    // Should have 'path' parameter
                    var readProps = inputSchema.GetProperty("properties");
                    readProps.TryGetProperty("path", out _).Should().BeTrue();
                    break;

                case "write_file":
                    // Should have 'path' and 'content' parameters
                    var writeProps = inputSchema.GetProperty("properties");
                    writeProps.TryGetProperty("path", out _).Should().BeTrue();
                    writeProps.TryGetProperty("content", out _).Should().BeTrue();
                    break;

                case "edit_file":
                    // Should have 'path', 'start_line', 'end_line', 'content'
                    var editProps = inputSchema.GetProperty("properties");
                    editProps.TryGetProperty("path", out _).Should().BeTrue();
                    editProps.TryGetProperty("start_line", out _).Should().BeTrue();
                    editProps.TryGetProperty("end_line", out _).Should().BeTrue();
                    editProps.TryGetProperty("content", out _).Should().BeTrue();
                    break;

                case "list_files":
                    // Should have 'pattern' parameter
                    var listProps = inputSchema.GetProperty("properties");
                    listProps.TryGetProperty("pattern", out _).Should().BeTrue();
                    break;

                case "search_files":
                    // Should have 'pattern' parameter
                    var searchProps = inputSchema.GetProperty("properties");
                    searchProps.TryGetProperty("pattern", out _).Should().BeTrue();
                    break;

                case "run_command":
                    // Should have 'executable' parameter
                    var runProps = inputSchema.GetProperty("properties");
                    runProps.TryGetProperty("executable", out _).Should().BeTrue();
                    break;
            }
        }
    }

    [Fact]
    public async Task Should_ExecuteToolsViaRegistry()
    {
        // Arrange
        var fileOps = new SafeFileOperations(null);
        _registry.Register(new ReadFileTool(_testRoot, fileOps));
        _registry.Register(new ListFilesTool(_testRoot, fileOps));

        // Create a test file
        var testFile = Path.Combine(_testRoot, "test.txt");
        await File.WriteAllTextAsync(testFile, "Test content");

        // Act - Execute read_file tool
        var readInput = JsonSerializer.SerializeToElement(new { path = "test.txt" });
        var readResult = await _registry.ExecuteAsync("read_file", readInput, CancellationToken.None);

        // Assert
        readResult.Should().Contain("Test content");
        readResult.Should().Contain("<untrusted_content>");
    }

    [Fact]
    public void Should_SerializeToClaudeAPIFormat()
    {
        // Arrange
        var fileOps = new SafeFileOperations(null);
        _registry.Register(new ReadFileTool(_testRoot, fileOps));

        // Act
        var definitions = _registry.GetToolDefinitions();
        var json = JsonSerializer.Serialize(definitions, SnakeCaseJsonOptions);

        // Assert - Verify Claude API format
        // Fields should be: name, description, input_schema
        json.Should().Contain("\"name\":");
        json.Should().Contain("\"description\":");
        json.Should().Contain("\"input_schema\":");

        // Verify it's valid JSON
        var parsed = JsonDocument.Parse(json);
        parsed.Should().NotBeNull();
    }

    [Fact]
    public void Should_AddAgentTools_RegisterAllServicesCorrectly()
    {
        // Arrange
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();

        // SessionFactory requires IClaudeClient, so register a mock
        services.AddSingleton<IClaudeClient>(new MockClaudeClient());

        // Act
        services.AddAgentTools(options =>
        {
            options.DefaultWorkingDirectory = _testRoot;
            options.CommandTimeoutSeconds = 60;
            options.RequireApprovalForWrites = false;
        });

        var serviceProvider = services.BuildServiceProvider();

        // Assert - Verify shared stateless services are registered
        var toolOptions = serviceProvider.GetService<ToolOptions>();
        toolOptions.Should().NotBeNull();
        toolOptions!.DefaultWorkingDirectory.Should().Be(_testRoot);
        toolOptions.CommandTimeoutSeconds.Should().Be(60);
        toolOptions.RequireApprovalForWrites.Should().BeFalse();

        var securityPolicy = serviceProvider.GetService<ISecurityPolicy>();
        securityPolicy.Should().NotBeNull();
        securityPolicy.Should().BeOfType<CommandPolicy>();

        // v0.4.0: IToolRegistry and ITool instances are no longer registered globally
        // They are created per-session by SessionFactory
        var toolRegistry = serviceProvider.GetService<IToolRegistry>();
        toolRegistry.Should().BeNull("IToolRegistry is created per-session by SessionFactory, not registered globally");

        var tools = serviceProvider.GetServices<ITool>().ToList();
        tools.Should().BeEmpty("ITool instances are created per-session by SessionFactory, not registered globally");

        // Verify ISessionFactory and ISessionManager are registered
        var sessionFactory = serviceProvider.GetService<ISessionFactory>();
        sessionFactory.Should().NotBeNull();
        sessionFactory.Should().BeOfType<SessionFactory>();

        var sessionManager = serviceProvider.GetService<ISessionManager>();
        sessionManager.Should().NotBeNull();
        sessionManager.Should().BeOfType<SessionManager>();
    }

    [Fact]
    public async Task Should_CreatePerSessionToolRegistry_ViaSessionFactory()
    {
        // Arrange - Set up DI container with all required services
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        
        // Add mock Claude client
        services.AddSingleton<IClaudeClient>(new MockClaudeClient());
        
        // Add agent tools
        services.AddAgentTools(options =>
        {
            options.DefaultWorkingDirectory = _testRoot;
            options.CommandTimeoutSeconds = 60;
            options.RequireApprovalForWrites = false;
            options.CeilingDirectory = "/"; // Allow all directories for testing
        });

        var serviceProvider = services.BuildServiceProvider();
        var sessionFactory = serviceProvider.GetRequiredService<ISessionFactory>();

        // Act - Create a session (which creates per-session tool registry)
        var sessionRequest = new SessionRequest(
            ProjectPath: _testRoot,
            MaxTokenBudget: 100_000,
            MaxToolCallBudget: 100);
        
        var session = sessionFactory.Create(sessionRequest);

        // Assert - Verify session has per-session tool registry
        session.Should().NotBeNull();
        session.Orchestrator.Should().NotBeNull();
        
        // Extract tool registry from orchestrator using reflection (same as Program.cs does)
        var orchestratorType = session.Orchestrator.GetType();
        var toolRegistryField = orchestratorType.GetField("_toolRegistry", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        toolRegistryField.Should().NotBeNull();
        
        var toolRegistry = toolRegistryField!.GetValue(session.Orchestrator) as IToolRegistry;
        toolRegistry.Should().NotBeNull();
        toolRegistry.Should().BeOfType<ToolRegistry>();

        // Verify all tools are registered in the per-session registry
        var definitions = toolRegistry!.GetToolDefinitions();
        var json = JsonSerializer.Serialize(definitions);
        var jsonDoc = JsonDocument.Parse(json);

        jsonDoc.RootElement.GetArrayLength().Should().Be(6);

        var toolNames = jsonDoc.RootElement
            .EnumerateArray()
            .Select(t => t.GetProperty("name").GetString())
            .ToList();

        toolNames.Should().Contain("read_file");
        toolNames.Should().Contain("write_file");
        toolNames.Should().Contain("edit_file");
        toolNames.Should().Contain("list_files");
        toolNames.Should().Contain("search_files");
        toolNames.Should().Contain("run_command");
        
        // Cleanup
        await session.DisposeAsync();
    }

    private sealed class MockClaudeClient : IClaudeClient
    {
        public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.CompletedTask.ConfigureAwait(false);
            yield break;
        }

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(0);
        }
    }
}
