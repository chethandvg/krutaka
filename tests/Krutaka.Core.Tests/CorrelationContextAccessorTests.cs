using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.Core.Tests;

public class CorrelationContextAccessorTests
{
    [Fact]
    public void Should_Initialize_WithNullCurrent()
    {
        // Arrange & Act
        var accessor = new CorrelationContextAccessor();

        // Assert
        accessor.Current.Should().BeNull();
    }

    [Fact]
    public void Should_SetAndGet_CorrelationContext()
    {
        // Arrange
        var accessor = new CorrelationContextAccessor();
        var context = new CorrelationContext(Guid.NewGuid());

        // Act
        accessor.Current = context;

        // Assert
        accessor.Current.Should().Be(context);
        accessor.Current?.SessionId.Should().Be(context.SessionId);
    }

    [Fact]
    public void Should_AllowSettingToNull()
    {
        // Arrange
        var accessor = new CorrelationContextAccessor();
        var context = new CorrelationContext(Guid.NewGuid());
        accessor.Current = context;

        // Act
        accessor.Current = null;

        // Assert
        accessor.Current.Should().BeNull();
    }

    [Fact]
    public async Task Should_FlowCorrelationContext_AcrossAsyncBoundaries()
    {
        // Arrange
        var accessor = new CorrelationContextAccessor();
        var sessionId = Guid.NewGuid();
        var context = new CorrelationContext(sessionId);
        accessor.Current = context;

        // Act - Access context in async method
        var retrievedSessionId = await GetSessionIdAsync(accessor);

        // Assert
        retrievedSessionId.Should().Be(sessionId);
    }

    [Fact]
    public async Task Should_IsolateCorrelationContext_BetweenParallelTasks()
    {
        // Arrange
        var accessor = new CorrelationContextAccessor();

        // Act - Run two parallel tasks with different contexts
        var task1 = Task.Run(async () =>
        {
            var sessionId1 = Guid.NewGuid();
            var context1 = new CorrelationContext(sessionId1);
            accessor.Current = context1;
            
            await Task.Delay(50);
            
            return accessor.Current?.SessionId ?? Guid.Empty;
        });

        var task2 = Task.Run(async () =>
        {
            var sessionId2 = Guid.NewGuid();
            var context2 = new CorrelationContext(sessionId2);
            accessor.Current = context2;
            
            await Task.Delay(50);
            
            return accessor.Current?.SessionId ?? Guid.Empty;
        });

        var results = await Task.WhenAll(task1, task2);

        // Assert - Each task should maintain its own context
        results[0].Should().NotBe(Guid.Empty);
        results[1].Should().NotBe(Guid.Empty);
        results[0].Should().NotBe(results[1]);
    }

    [Fact]
    public async Task Should_MaintainCorrelationContext_ThroughNestedAsyncCalls()
    {
        // Arrange
        var accessor = new CorrelationContextAccessor();
        var sessionId = Guid.NewGuid();
        var context = new CorrelationContext(sessionId);
        context.IncrementTurn();
        accessor.Current = context;

        // Act - Nested async calls
        var result = await Level1Async(accessor);

        // Assert
        result.SessionId.Should().Be(sessionId);
        result.TurnId.Should().Be(1); // Should maintain the turn ID
    }

    [Fact]
    public void Should_AllowMultipleInstancesWithIndependentStorage()
    {
        // Arrange
        var accessor1 = new CorrelationContextAccessor();
        var accessor2 = new CorrelationContextAccessor();
        
        var sessionId1 = Guid.NewGuid();
        var sessionId2 = Guid.NewGuid();
        
        var context1 = new CorrelationContext(sessionId1);
        var context2 = new CorrelationContext(sessionId2);

        // Act
        accessor1.Current = context1;
        accessor2.Current = context2;

        // Assert - Each accessor should maintain its own AsyncLocal storage
        accessor1.Current?.SessionId.Should().Be(sessionId1);
        accessor2.Current?.SessionId.Should().Be(sessionId2);
    }

    // Helper methods for async flow testing
    private static async Task<Guid> GetSessionIdAsync(CorrelationContextAccessor accessor)
    {
        await Task.Delay(10);
        return accessor.Current?.SessionId ?? Guid.Empty;
    }

    private static async Task<(Guid SessionId, int TurnId)> Level1Async(CorrelationContextAccessor accessor)
    {
        await Task.Delay(10);
        return await Level2Async(accessor);
    }

    private static async Task<(Guid SessionId, int TurnId)> Level2Async(CorrelationContextAccessor accessor)
    {
        await Task.Delay(10);
        var current = accessor.Current;
        return (current?.SessionId ?? Guid.Empty, current?.TurnId ?? 0);
    }
}
