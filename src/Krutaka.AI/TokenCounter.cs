using System.Collections.Concurrent;
using System.Globalization;
using Krutaka.Core;
using Microsoft.Extensions.Logging;

namespace Krutaka.AI;

/// <summary>
/// Provides token counting with caching to avoid redundant API calls.
/// Uses the Claude API's /v1/messages/count_tokens endpoint for accurate counts.
/// </summary>
public sealed partial class TokenCounter
{
    private readonly IClaudeClient _claudeClient;
    private readonly ILogger<TokenCounter> _logger;
    private readonly ConcurrentDictionary<string, CachedTokenCount> _cache;
    private readonly int _cacheMaxSize;
    private readonly TimeSpan _cacheExpiry;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenCounter"/> class.
    /// </summary>
    /// <param name="claudeClient">The Claude API client.</param>
    /// <param name="logger">The logger instance.</param>
    /// <param name="cacheMaxSize">Maximum number of cached entries (default: 100).</param>
    /// <param name="cacheExpiryMinutes">Cache expiry time in minutes (default: 60).</param>
    public TokenCounter(
        IClaudeClient claudeClient,
        ILogger<TokenCounter> logger,
        int cacheMaxSize = 100,
        int cacheExpiryMinutes = 60)
    {
        _claudeClient = claudeClient;
        _logger = logger;
        _cache = new ConcurrentDictionary<string, CachedTokenCount>();
        _cacheMaxSize = cacheMaxSize;
        _cacheExpiry = TimeSpan.FromMinutes(cacheExpiryMinutes);
    }

    /// <summary>
    /// Counts tokens in a message sequence using Claude's tokenizer.
    /// Uses caching to avoid redundant API calls for recently counted messages.
    /// </summary>
    /// <param name="messages">The messages to count tokens for.</param>
    /// <param name="systemPrompt">The system prompt to include in the count.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>The total token count.</returns>
    public async Task<int> CountTokensAsync(
        IReadOnlyList<object> messages,
        string systemPrompt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ArgumentNullException.ThrowIfNull(systemPrompt);

        // Generate cache key from messages and system prompt
        var cacheKey = GenerateCacheKey(messages, systemPrompt);

        // Check cache first
        if (_cache.TryGetValue(cacheKey, out var cachedCount))
        {
            // Verify cache entry hasn't expired
            if (DateTimeOffset.UtcNow - cachedCount.Timestamp < _cacheExpiry)
            {
                LogCacheHit(cachedCount.TokenCount);
                return cachedCount.TokenCount;
            }

            // Cache entry expired, remove it
            _cache.TryRemove(cacheKey, out _);
        }

        // Count tokens via API
        LogCountingTokens(messages.Count);
        var tokenCount = await _claudeClient.CountTokensAsync(messages, systemPrompt, cancellationToken).ConfigureAwait(false);

        // Store in cache
        _cache[cacheKey] = new CachedTokenCount(tokenCount, DateTimeOffset.UtcNow);

        // Evict oldest entries if cache is full
        if (_cache.Count > _cacheMaxSize)
        {
            EvictOldestCacheEntries();
        }

        return tokenCount;
    }

    /// <summary>
    /// Generates a cache key from messages and system prompt.
    /// Uses a simple hash-based approach for efficiency.
    /// </summary>
    private static string GenerateCacheKey(IReadOnlyList<object> messages, string systemPrompt)
    {
        // Simple hash-based key combining message count, system prompt, and content hash
        var hash = HashCode.Combine(messages.Count, systemPrompt);
        
        // Include first and last message content for uniqueness
        if (messages.Count > 0)
        {
            hash = HashCode.Combine(hash, messages[0].GetHashCode());
            if (messages.Count > 1)
            {
                hash = HashCode.Combine(hash, messages[^1].GetHashCode());
            }
        }

        return hash.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Evicts the oldest cache entries when cache size exceeds the maximum.
    /// Removes 20% of entries sorted by timestamp.
    /// </summary>
    private void EvictOldestCacheEntries()
    {
        var entriesToRemove = (int)(_cacheMaxSize * 0.2);
        var oldestEntries = _cache
            .OrderBy(kvp => kvp.Value.Timestamp)
            .Take(entriesToRemove)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in oldestEntries)
        {
            _cache.TryRemove(key, out _);
        }

        LogCacheEviction(entriesToRemove);
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Token count cache hit: {TokenCount} tokens")]
    partial void LogCacheHit(int tokenCount);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Counting tokens for {MessageCount} messages via API")]
    partial void LogCountingTokens(int messageCount);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Evicted {Count} oldest cache entries")]
    partial void LogCacheEviction(int count);

    /// <summary>
    /// Cached token count with timestamp.
    /// </summary>
    private sealed record CachedTokenCount(int TokenCount, DateTimeOffset Timestamp);
}
