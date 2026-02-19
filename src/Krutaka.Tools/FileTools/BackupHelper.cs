using System.Globalization;

namespace Krutaka.Tools;

/// <summary>
/// Helper class for creating backup copies of files before destructive operations.
/// </summary>
internal static class BackupHelper
{
    /// <summary>
    /// Creates a backup copy of the specified file in a temporary directory.
    /// Uses millisecond-precision timestamps and GUIDs to prevent collisions.
    /// </summary>
    /// <param name="filePath">The file to backup.</param>
    /// <returns>The path to the backup file.</returns>
    /// <exception cref="ArgumentNullException">Thrown when filePath is null.</exception>
    /// <exception cref="IOException">Thrown when backup creation fails.</exception>
    public static string CreateBackup(string filePath)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        var fileName = Path.GetFileName(filePath);
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff", CultureInfo.InvariantCulture);
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        var backupFileName = $"{fileName}.{timestamp}.{uniqueId}.bak";
        var backupPath = Path.Combine(Path.GetTempPath(), "krutaka-backups", backupFileName);

        var backupDir = Path.GetDirectoryName(backupPath);
        if (!string.IsNullOrEmpty(backupDir))
        {
            Directory.CreateDirectory(backupDir);
        }

        // Use overwrite: false to ensure we never silently replace an existing backup
        // If a collision occurs (extremely unlikely with milliseconds + GUID), throw an exception
        File.Copy(filePath, backupPath, overwrite: false);
        return backupPath;
    }
}
