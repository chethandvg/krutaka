using Krutaka.Core;

namespace Krutaka.Memory;

/// <summary>
/// Service for managing the curated MEMORY.md file.
/// Provides read access and append-only updates with duplicate detection.
/// </summary>
public sealed class MemoryFileService : IDisposable
{
    private readonly string _memoryFilePath;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="MemoryFileService"/> class.
    /// </summary>
    /// <param name="memoryFilePath">The path to the MEMORY.md file.</param>
    public MemoryFileService(string memoryFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(memoryFilePath, nameof(memoryFilePath));
        _memoryFilePath = memoryFilePath;
    }

    /// <summary>
    /// Reads the entire contents of the MEMORY.md file.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The contents of MEMORY.md, or empty string if file doesn't exist.</returns>
    public async Task<string> ReadMemoryAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _fileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_memoryFilePath))
            {
                return string.Empty;
            }

            return await File.ReadAllTextAsync(_memoryFilePath, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    /// <summary>
    /// Appends a key-value pair to the MEMORY.md file under the appropriate section header.
    /// Prevents duplicates by checking existing content.
    /// Uses atomic writes to prevent corruption.
    /// </summary>
    /// <param name="key">The section/category key (e.g., "User Preferences", "Project Context").</param>
    /// <param name="value">The fact or information to remember.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the entry was added, false if it was a duplicate.</returns>
    public async Task<bool> AppendToMemoryAsync(
        string key,
        string value,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        ArgumentException.ThrowIfNullOrWhiteSpace(key, nameof(key));
        ArgumentException.ThrowIfNullOrWhiteSpace(value, nameof(value));

        await _fileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Ensure directory exists
            var directory = Path.GetDirectoryName(_memoryFilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // Read existing content
            var existingContent = File.Exists(_memoryFilePath)
                ? await File.ReadAllTextAsync(_memoryFilePath, cancellationToken).ConfigureAwait(false)
                : string.Empty;

            // Check for duplicates (case-insensitive)
            var normalizedValue = value.Trim();
            if (existingContent.Contains(normalizedValue, StringComparison.OrdinalIgnoreCase))
            {
                return false; // Duplicate found, skip
            }

            // Build the new entry
            var sectionHeader = $"## {key}";
            var entry = $"- {normalizedValue}";
            var newContent = new System.Text.StringBuilder(existingContent);

            // Check if section already exists
            if (existingContent.Contains(sectionHeader, StringComparison.Ordinal))
            {
                // Find the section and append to it
                var lines = existingContent.Split('\n').ToList();
                var sectionIndex = lines.FindIndex(l => l.Trim() == sectionHeader);

                if (sectionIndex >= 0)
                {
                    // Find where to insert (after section header, before next section or end)
                    var insertIndex = sectionIndex + 1;
                    while (insertIndex < lines.Count &&
                           !lines[insertIndex].StartsWith("##", StringComparison.Ordinal) &&
                           !string.IsNullOrWhiteSpace(lines[insertIndex]))
                    {
                        insertIndex++;
                    }

                    lines.Insert(insertIndex, entry);
                    newContent.Clear();
                    newContent.AppendJoin('\n', lines);
                }
            }
            else
            {
                // Add new section at the end
                if (newContent.Length > 0 && !existingContent.EndsWith('\n'))
                {
                    newContent.AppendLine();
                }

                if (newContent.Length > 0)
                {
                    newContent.AppendLine(); // Blank line before section
                }

                newContent.AppendLine(sectionHeader);
                newContent.AppendLine(entry);
            }

            // Atomic write: temp file → move
            var tempFile = _memoryFilePath + ".tmp";
            await File.WriteAllTextAsync(tempFile, newContent.ToString(), cancellationToken).ConfigureAwait(false);
            File.Move(tempFile, _memoryFilePath, overwrite: true);

            return true; // Entry added
        }
        finally
        {
            _fileLock.Release();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _fileLock.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
