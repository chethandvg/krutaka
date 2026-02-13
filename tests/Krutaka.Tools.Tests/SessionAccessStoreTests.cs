using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Tests for InMemorySessionAccessStore - session-scoped directory access grant management.
/// Covers grant/revoke operations, TTL enforcement, max grants limits, thread-safety, and access level validation.
/// </summary>
public sealed class SessionAccessStoreTests
{
    private const string TestPath1 = @"C:\Projects\MyApp";
    private const string TestPath2 = @"C:\Projects\OtherApp";
    private const string TestPath3 = @"C:\Projects\ThirdApp";

    #region Basic Grant and Verify Tests

    [Fact]
    public async Task Should_GrantAndVerifyAccess_WhenPathAndLevelMatch()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Act
        await store.GrantAccessAsync(
            TestPath1,
            AccessLevel.ReadOnly,
            expiresAfter: null,
            justification: "Testing",
            GrantSource.User,
            CancellationToken.None);

        var isGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None);

        // Assert
        isGranted.Should().BeTrue();
    }

    [Fact]
    public async Task Should_ReturnFalse_WhenNoGrantExists()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Act
        var isGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None);

        // Assert
        isGranted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_OverwriteExistingGrant_WhenPathIsGrantedAgain()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        await store.GrantAccessAsync(
            TestPath1,
            AccessLevel.ReadOnly,
            expiresAfter: TimeSpan.FromMinutes(5),
            justification: "First grant",
            GrantSource.User,
            CancellationToken.None);

        // Act - Grant same path again with different level
        await store.GrantAccessAsync(
            TestPath1,
            AccessLevel.ReadWrite,
            expiresAfter: TimeSpan.FromMinutes(10),
            justification: "Second grant",
            GrantSource.Policy,
            CancellationToken.None);

        var isReadOnlyGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None);
        var isReadWriteGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadWrite, CancellationToken.None);

        // Assert - Should have the new ReadWrite grant (which covers ReadOnly)
        isReadOnlyGranted.Should().BeTrue();
        isReadWriteGranted.Should().BeTrue();
    }

    #endregion

    #region Revoke Tests

    [Fact]
    public async Task Should_RevokeAccess_WhenPathIsRevoked()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        await store.GrantAccessAsync(
            TestPath1,
            AccessLevel.ReadOnly,
            expiresAfter: null,
            justification: "Testing",
            GrantSource.User,
            CancellationToken.None);

        // Act
        await store.RevokeAccessAsync(TestPath1, CancellationToken.None);
        var isGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None);

        // Assert
        isGranted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_DoNothing_WhenRevokingNonExistentGrant()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Act - Revoke a path that was never granted
        await store.RevokeAccessAsync(TestPath1, CancellationToken.None);

        // Assert - Should not throw
        var isGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None);
        isGranted.Should().BeFalse();
    }

    #endregion

    #region TTL Expiry Tests

    [Fact]
    public async Task Should_RemoveGrant_WhenTtlExpires()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Grant with very short TTL (100ms)
        await store.GrantAccessAsync(
            TestPath1,
            AccessLevel.ReadOnly,
            expiresAfter: TimeSpan.FromMilliseconds(100),
            justification: "Testing TTL",
            GrantSource.User,
            CancellationToken.None);

        // Verify grant exists immediately
        var isGrantedBefore = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None);
        isGrantedBefore.Should().BeTrue();

        // Act - Wait for TTL to expire
        await Task.Delay(TimeSpan.FromMilliseconds(200));

        // Verify grant is now expired (IsGrantedAsync auto-prunes)
        var isGrantedAfter = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None);

        // Assert
        isGrantedAfter.Should().BeFalse();
    }

    [Fact]
    public async Task Should_NotExpire_WhenTtlIsNull()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        await store.GrantAccessAsync(
            TestPath1,
            AccessLevel.ReadOnly,
            expiresAfter: null, // No TTL
            justification: "Session lifetime",
            GrantSource.User,
            CancellationToken.None);

        // Act - Wait a bit
        await Task.Delay(TimeSpan.FromMilliseconds(100));

        var isGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None);

        // Assert - Should still be granted
        isGranted.Should().BeTrue();
    }

    [Fact]
    public async Task Should_ReturnCorrectCount_WhenPruningExpiredGrants()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Grant 3 paths: 2 with short TTL, 1 with no TTL
        await store.GrantAccessAsync(TestPath1, AccessLevel.ReadOnly, TimeSpan.FromMilliseconds(100), "Test", GrantSource.User, CancellationToken.None);
        await store.GrantAccessAsync(TestPath2, AccessLevel.ReadOnly, TimeSpan.FromMilliseconds(100), "Test", GrantSource.User, CancellationToken.None);
        await store.GrantAccessAsync(TestPath3, AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);

        // Wait for expiry
        await Task.Delay(TimeSpan.FromMilliseconds(200));

        // Act
        var prunedCount = await store.PruneExpiredAsync(CancellationToken.None);

        // Assert
        prunedCount.Should().Be(2); // Two grants should have expired
    }

    #endregion

    #region Max Concurrent Grants Tests

    [Fact]
    public async Task Should_EnforceMaxGrants_WhenLimitReached()
    {
        // Arrange - Max 3 grants
        using var store = new InMemorySessionAccessStore(maxConcurrentGrants: 3);

        // Grant 3 paths
        await store.GrantAccessAsync(@"C:\Path1", AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);
        await store.GrantAccessAsync(@"C:\Path2", AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);
        await store.GrantAccessAsync(@"C:\Path3", AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);

        // Act - Try to grant a 4th path
        var act = async () => await store.GrantAccessAsync(@"C:\Path4", AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Maximum number of concurrent grants*");
    }

    [Fact]
    public async Task Should_AllowNewGrant_WhenMaxGrantsReachedButExpiredGrantsPruned()
    {
        // Arrange - Max 2 grants
        using var store = new InMemorySessionAccessStore(maxConcurrentGrants: 2);

        // Grant 2 paths with short TTL
        await store.GrantAccessAsync(@"C:\Path1", AccessLevel.ReadOnly, TimeSpan.FromMilliseconds(100), "Test", GrantSource.User, CancellationToken.None);
        await store.GrantAccessAsync(@"C:\Path2", AccessLevel.ReadOnly, TimeSpan.FromMilliseconds(100), "Test", GrantSource.User, CancellationToken.None);

        // Wait for expiry
        await Task.Delay(TimeSpan.FromMilliseconds(200));

        // Act - Grant a new path (should prune expired ones first)
        await store.GrantAccessAsync(@"C:\Path3", AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);

        var isGranted = await store.IsGrantedAsync(@"C:\Path3", AccessLevel.ReadOnly, CancellationToken.None);

        // Assert
        isGranted.Should().BeTrue();
    }

    [Fact]
    public async Task Should_AllowOverwrite_WhenMaxGrantsReachedButPathAlreadyExists()
    {
        // Arrange - Max 2 grants
        using var store = new InMemorySessionAccessStore(maxConcurrentGrants: 2);

        await store.GrantAccessAsync(@"C:\Path1", AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);
        await store.GrantAccessAsync(@"C:\Path2", AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);

        // Act - Update existing grant (should not throw)
        await store.GrantAccessAsync(@"C:\Path1", AccessLevel.ReadWrite, null, "Updated", GrantSource.User, CancellationToken.None);

        var isGranted = await store.IsGrantedAsync(@"C:\Path1", AccessLevel.ReadWrite, CancellationToken.None);

        // Assert
        isGranted.Should().BeTrue();
    }

    #endregion

    #region Access Level Tests

    [Fact]
    public async Task Should_DenyAccess_WhenRequestedLevelExceedsGrantedLevel()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Grant ReadOnly access
        await store.GrantAccessAsync(
            TestPath1,
            AccessLevel.ReadOnly,
            expiresAfter: null,
            justification: "Testing",
            GrantSource.User,
            CancellationToken.None);

        // Act - Request ReadWrite access
        var isGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadWrite, CancellationToken.None);

        // Assert
        isGranted.Should().BeFalse();
    }

    [Fact]
    public async Task Should_AllowAccess_WhenReadWriteGrantCoversReadOnlyRequest()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Grant ReadWrite access
        await store.GrantAccessAsync(
            TestPath1,
            AccessLevel.ReadWrite,
            expiresAfter: null,
            justification: "Testing",
            GrantSource.User,
            CancellationToken.None);

        // Act - Request ReadOnly access (should be covered by ReadWrite)
        var isGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None);

        // Assert
        isGranted.Should().BeTrue();
    }

    [Fact]
    public async Task Should_DenyExecuteAccess_WhenOnlyReadWriteGranted()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Grant ReadWrite access
        await store.GrantAccessAsync(
            TestPath1,
            AccessLevel.ReadWrite,
            expiresAfter: null,
            justification: "Testing",
            GrantSource.User,
            CancellationToken.None);

        // Act - Request Execute access (not covered by ReadWrite)
        var isGranted = await store.IsGrantedAsync(TestPath1, AccessLevel.Execute, CancellationToken.None);

        // Assert
        isGranted.Should().BeFalse();
    }

    #endregion

    #region Get Active Grants Tests

    [Fact]
    public async Task Should_ReturnActiveGrants_WhenGrantsExist()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        await store.GrantAccessAsync(TestPath1, AccessLevel.ReadOnly, null, "Test 1", GrantSource.User, CancellationToken.None);
        await store.GrantAccessAsync(TestPath2, AccessLevel.ReadWrite, null, "Test 2", GrantSource.AutoGrant, CancellationToken.None);

        // Act
        var grants = await store.GetActiveGrantsAsync(CancellationToken.None);

        // Assert
        grants.Should().HaveCount(2);
        grants.Should().ContainSingle(g => g.Path.Equals(TestPath1, StringComparison.OrdinalIgnoreCase));
        grants.Should().ContainSingle(g => g.Path.Equals(TestPath2, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Should_ExcludeExpiredGrants_WhenGettingActiveGrants()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        await store.GrantAccessAsync(TestPath1, AccessLevel.ReadOnly, TimeSpan.FromMilliseconds(100), "Test", GrantSource.User, CancellationToken.None);
        await store.GrantAccessAsync(TestPath2, AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);

        // Wait for first grant to expire
        await Task.Delay(TimeSpan.FromMilliseconds(200));

        // Act
        var grants = await store.GetActiveGrantsAsync(CancellationToken.None);

        // Assert
        grants.Should().HaveCount(1);
        grants.Should().ContainSingle(g => g.Path.Equals(TestPath2, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Should_ReturnEmptyList_WhenNoGrantsExist()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Act
        var grants = await store.GetActiveGrantsAsync(CancellationToken.None);

        // Assert
        grants.Should().BeEmpty();
    }

    #endregion

    #region Thread-Safety Tests

    [Fact]
    public async Task Should_HandleConcurrentGrants_ThreadSafely()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore(maxConcurrentGrants: 100);
        var tasks = new List<Task>();

        // Act - Grant 50 paths concurrently
        for (int i = 0; i < 50; i++)
        {
            var path = $@"C:\Path{i}";
            tasks.Add(store.GrantAccessAsync(path, AccessLevel.ReadOnly, null, $"Test {i}", GrantSource.User, CancellationToken.None));
        }

        await Task.WhenAll(tasks);

        // Verify all grants exist
        var grants = await store.GetActiveGrantsAsync(CancellationToken.None);

        // Assert
        grants.Should().HaveCount(50);
    }

    [Fact]
    public async Task Should_HandleConcurrentReadsDuringPruning_ThreadSafely()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();
        await store.GrantAccessAsync(TestPath1, AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);

        var tasks = new List<Task<bool>>();

        // Act - Multiple concurrent IsGrantedAsync calls (which trigger pruning)
        for (int i = 0; i < 20; i++)
        {
            tasks.Add(store.IsGrantedAsync(TestPath1, AccessLevel.ReadOnly, CancellationToken.None));
        }

        var results = await Task.WhenAll(tasks);

        // Assert - All reads should succeed and return true
        results.Should().AllBeEquivalentTo(true);
    }

    #endregion

    #region Validation Tests

    [Fact]
    public async Task Should_ThrowArgumentException_WhenGrantingWithNullPath()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Act
        var act = async () => await store.GrantAccessAsync(null!, AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowArgumentException_WhenGrantingWithEmptyJustification()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Act
        var act = async () => await store.GrantAccessAsync(TestPath1, AccessLevel.ReadOnly, null, "", GrantSource.User, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowArgumentException_WhenCheckingGrantWithNullPath()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Act
        var act = async () => await store.IsGrantedAsync(null!, AccessLevel.ReadOnly, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public void Should_ThrowArgumentOutOfRangeException_WhenMaxGrantsIsZero()
    {
        // Act
        var act = () => new InMemorySessionAccessStore(maxConcurrentGrants: 0);

        // Assert
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Should_ThrowArgumentOutOfRangeException_WhenMaxGrantsIsNegative()
    {
        // Act
        var act = () => new InMemorySessionAccessStore(maxConcurrentGrants: -1);

        // Assert
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    #endregion

    #region Path Case-Insensitivity Tests

    [Fact]
    public async Task Should_MatchGrant_CaseInsensitively()
    {
        // Arrange
        using var store = new InMemorySessionAccessStore();

        // Grant with lowercase path
        await store.GrantAccessAsync(@"c:\projects\myapp", AccessLevel.ReadOnly, null, "Test", GrantSource.User, CancellationToken.None);

        // Act - Check with uppercase path
        var isGranted = await store.IsGrantedAsync(@"C:\PROJECTS\MYAPP", AccessLevel.ReadOnly, CancellationToken.None);

        // Assert
        isGranted.Should().BeTrue();
    }

    #endregion
}
