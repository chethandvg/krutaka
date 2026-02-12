using System.Collections.Concurrent;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// In-memory implementation of ISessionAccessStore with TTL enforcement and thread-safety.
/// Stores session-scoped directory access grants in a concurrent dictionary with automatic expiry pruning.
/// </summary>
public sealed class InMemorySessionAccessStore : ISessionAccessStore, IDisposable
{
    private readonly ConcurrentDictionary<string, SessionAccessGrant> _grants;
    private readonly SemaphoreSlim _pruneLock;
    private readonly int _maxConcurrentGrants;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemorySessionAccessStore"/> class.
    /// </summary>
    /// <param name="maxConcurrentGrants">Maximum number of concurrent directory grants allowed (default: 10).</param>
    public InMemorySessionAccessStore(int maxConcurrentGrants = 10)
    {
        if (maxConcurrentGrants <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrentGrants), "Must be greater than zero.");
        }

        _grants = new ConcurrentDictionary<string, SessionAccessGrant>(StringComparer.OrdinalIgnoreCase);
        _pruneLock = new SemaphoreSlim(1, 1);
        _maxConcurrentGrants = maxConcurrentGrants;
    }

    /// <inheritdoc/>
    public async Task<bool> IsGrantedAsync(string path, AccessLevel requestedLevel, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        // Automatically prune expired grants before checking
        await PruneExpiredAsync(cancellationToken).ConfigureAwait(false);

        // Check if we have a matching grant
        if (_grants.TryGetValue(path, out var grant))
        {
            // Verify the grant hasn't expired (double-check after pruning)
            if (grant.IsExpired(DateTimeOffset.UtcNow))
            {
                return false;
            }

            // Verify the granted access level covers the requested level
            return grant.CoversAccessLevel(requestedLevel);
        }

        return false;
    }

    /// <inheritdoc/>
    public async Task GrantAccessAsync(
        string path,
        AccessLevel grantedLevel,
        TimeSpan? expiresAfter,
        string justification,
        GrantSource grantedBy,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(justification);

        // Prune expired grants first to free up space
        await PruneExpiredAsync(cancellationToken).ConfigureAwait(false);

        // Check if we've reached the maximum number of grants
        // Use _pruneLock to ensure atomic check-and-add
        await _pruneLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Check again after acquiring lock (another thread might have added)
            if (_grants.Count >= _maxConcurrentGrants && !_grants.ContainsKey(path))
            {
                throw new InvalidOperationException(
                    $"Maximum number of concurrent grants ({_maxConcurrentGrants}) has been reached. " +
                    "Revoke existing grants or wait for them to expire.");
            }

            var now = DateTimeOffset.UtcNow;
            var expiresAt = expiresAfter.HasValue ? now.Add(expiresAfter.Value) : (DateTimeOffset?)null;

            var grant = new SessionAccessGrant(
                Path: path,
                AccessLevel: grantedLevel,
                GrantedAt: now,
                ExpiresAt: expiresAt,
                Justification: justification,
                GrantedBy: grantedBy
            );

            // AddOrUpdate is atomic - updates existing grant or adds new one
            _grants.AddOrUpdate(path, grant, (_, _) => grant);
        }
        finally
        {
            _pruneLock.Release();
        }
    }

    /// <inheritdoc/>
    public Task RevokeAccessAsync(string path, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        _grants.TryRemove(path, out _);

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<SessionAccessGrant>> GetActiveGrantsAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var now = DateTimeOffset.UtcNow;

        // Filter out expired grants and return as read-only list
        var activeGrants = _grants.Values
            .Where(grant => !grant.IsExpired(now))
            .ToList()
            .AsReadOnly();

        return Task.FromResult<IReadOnlyList<SessionAccessGrant>>(activeGrants);
    }

    /// <inheritdoc/>
    public async Task<int> PruneExpiredAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var prunedCount = 0;

        // Use semaphore to prevent concurrent pruning (defensive - not strictly required)
        await _pruneLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var now = DateTimeOffset.UtcNow;

            // Find all expired grants
            var expiredPaths = _grants
                .Where(kvp => kvp.Value.IsExpired(now))
                .Select(kvp => kvp.Key)
                .ToList();

            // Remove expired grants
            foreach (var path in expiredPaths)
            {
                if (_grants.TryRemove(path, out _))
                {
                    prunedCount++;
                }
            }
        }
        finally
        {
            _pruneLock.Release();
        }

        return prunedCount;
    }

    /// <summary>
    /// Disposes the resources used by this instance.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _pruneLock.Dispose();
        _disposed = true;
    }
}
