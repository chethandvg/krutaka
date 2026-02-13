using System.Collections.Concurrent;

namespace Krutaka.Core;

/// <summary>
/// Implementation of command approval cache for tracking approved commands within a session.
/// Thread-safe and uses time-based expiry for approvals.
/// </summary>
public sealed class CommandApprovalCache : ICommandApprovalCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _approvals = new();

    /// <inheritdoc/>
    public bool IsApproved(string commandSignature)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commandSignature);
        
        // Clean up expired approvals first
        CleanupExpiredApprovals();
        
        if (_approvals.TryGetValue(commandSignature, out var expiryTime))
        {
            return DateTimeOffset.UtcNow < expiryTime;
        }
        
        return false;
    }

    /// <inheritdoc/>
    public void AddApproval(string commandSignature, TimeSpan ttl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commandSignature);
        
        var expiryTime = DateTimeOffset.UtcNow.Add(ttl);
        _approvals[commandSignature] = expiryTime;
    }

    /// <inheritdoc/>
    public void RemoveApproval(string commandSignature)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commandSignature);
        _approvals.TryRemove(commandSignature, out _);
    }

    /// <summary>
    /// Removes expired approvals from the cache.
    /// </summary>
    private void CleanupExpiredApprovals()
    {
        var now = DateTimeOffset.UtcNow;
        var expiredKeys = _approvals
            .Where(kvp => now >= kvp.Value)
            .Select(kvp => kvp.Key)
            .ToList();
        
        foreach (var key in expiredKeys)
        {
            _approvals.TryRemove(key, out _);
        }
    }
}
