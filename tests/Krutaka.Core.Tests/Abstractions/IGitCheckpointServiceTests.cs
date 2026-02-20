using FluentAssertions;

namespace Krutaka.Core.Tests;

public class IGitCheckpointServiceTests
{
    private sealed class StubGitCheckpointService : IGitCheckpointService
    {
        private readonly List<CheckpointInfo> _checkpoints = [];

        public Task<string> CreateCheckpointAsync(string message, CancellationToken ct)
        {
            var id = $"checkpoint-{_checkpoints.Count + 1}";
            _checkpoints.Add(new CheckpointInfo(id, message, DateTime.UtcNow, 0));
            return Task.FromResult(id);
        }

        public Task RollbackToCheckpointAsync(string checkpointId, CancellationToken ct)
        {
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<CheckpointInfo>> ListCheckpointsAsync(CancellationToken ct)
        {
            return Task.FromResult<IReadOnlyList<CheckpointInfo>>(_checkpoints.AsReadOnly());
        }
    }

    [Fact]
    public void IGitCheckpointService_Should_BeAssignableFromStubImplementation()
    {
        // Act
        IGitCheckpointService service = new StubGitCheckpointService();

        // Assert
        service.Should().NotBeNull();
        service.Should().BeAssignableTo<IGitCheckpointService>();
    }

    [Fact]
    public async Task CreateCheckpointAsync_Should_ReturnNonEmptyId()
    {
        // Arrange
        IGitCheckpointService service = new StubGitCheckpointService();

        // Act
        string id = await service.CreateCheckpointAsync("Before refactor", CancellationToken.None);

        // Assert
        id.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ListCheckpointsAsync_Should_ReturnCreatedCheckpoints()
    {
        // Arrange
        IGitCheckpointService service = new StubGitCheckpointService();
        await service.CreateCheckpointAsync("Checkpoint 1", CancellationToken.None);
        await service.CreateCheckpointAsync("Checkpoint 2", CancellationToken.None);

        // Act
        IReadOnlyList<CheckpointInfo> checkpoints = await service.ListCheckpointsAsync(CancellationToken.None);

        // Assert
        checkpoints.Should().HaveCount(2);
        checkpoints[0].Message.Should().Be("Checkpoint 1");
        checkpoints[1].Message.Should().Be("Checkpoint 2");
    }

    [Fact]
    public async Task RollbackToCheckpointAsync_Should_Complete_WithValidId()
    {
        // Arrange
        IGitCheckpointService service = new StubGitCheckpointService();
        string id = await service.CreateCheckpointAsync("Before change", CancellationToken.None);

        // Act & Assert — should not throw
        await service.Invoking(s => s.RollbackToCheckpointAsync(id, CancellationToken.None))
            .Should().NotThrowAsync();
    }
}
