namespace Krutaka.Memory.Tests;

/// <summary>
/// Helper class for creating test directories that work in both local development
/// and CI environments. On Windows CI runners, Path.GetTempPath() returns a path 
/// in LocalAppData which may cause issues. This helper uses an alternative path 
/// that's safe for testing.
/// </summary>
internal static class TestDirectoryHelper
{
    /// <summary>
    /// Gets a unique test directory path that's safe for use in CI environments.
    /// </summary>
    /// <param name="testName">A name to include in the directory path for identification.</param>
    /// <returns>A unique directory path that avoids LocalAppData restrictions.</returns>
    public static string GetTestDirectory(string testName)
    {
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        
        if (OperatingSystem.IsWindows())
        {
            // Try RUNNER_TEMP first (GitHub Actions), then fall back to C:\temp
            // This avoids triggering the LocalAppData security check and reduces
            // file lock issues with SQLite on Windows
            var basePath = GetWritableWindowsBasePath();
            return Path.Combine(basePath, $"krutaka-{testName}-{uniqueId}");
        }
        else
        {
            // On Linux/Mac, /tmp is standard and not restricted
            return Path.Combine("/tmp", $"krutaka-{testName}-{uniqueId}");
        }
    }

    /// <summary>
    /// Gets a writable base path for Windows that avoids LocalAppData.
    /// Tries RUNNER_TEMP (CI), then C:\temp, with fallback to user profile.
    /// </summary>
    private static string GetWritableWindowsBasePath()
    {
        // 1. Try RUNNER_TEMP environment variable (GitHub Actions)
        var runnerTemp = Environment.GetEnvironmentVariable("RUNNER_TEMP");
        if (!string.IsNullOrEmpty(runnerTemp) && TryEnsureDirectory(runnerTemp))
        {
            return runnerTemp;
        }

        // 2. Try C:\temp (common CI-safe location)
        const string cTemp = @"C:\temp";
        if (TryEnsureDirectory(cTemp))
        {
            return cTemp;
        }

        // 3. Fall back to user profile subdirectory (always writable)
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var fallbackPath = Path.Combine(userProfile, ".krutaka-test-temp");
        TryEnsureDirectory(fallbackPath);
        return fallbackPath;
    }

    /// <summary>
    /// Attempts to ensure a directory exists.
    /// </summary>
    private static bool TryEnsureDirectory(string path)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <summary>
    /// Safely deletes a test directory with retry logic for SQLite file locks.
    /// Uses longer delays and more retries than typical due to SQLite connection pooling.
    /// </summary>
    /// <param name="path">The directory path to delete.</param>
    /// <param name="maxRetries">Maximum number of retry attempts.</param>
    /// <param name="delayMs">Delay in milliseconds between retries.</param>
    public static void TryDeleteDirectory(string path, int maxRetries = 5, int delayMs = 200)
    {
        if (!Directory.Exists(path))
        {
            return;
        }
        
        for (int i = 0; i < maxRetries; i++)
        {
            try
            {
                Directory.Delete(path, true);
                return;
            }
            catch (IOException) when (i < maxRetries - 1)
            {
                // Wait a bit before retrying to allow SQLite connections to be released
                Thread.Sleep(delayMs);
            }
            catch (UnauthorizedAccessException) when (i < maxRetries - 1)
            {
                // Transient access issues (e.g., file locks, read-only flags) can occur on Windows
                Thread.Sleep(delayMs);
            }
            catch (IOException ex)
            {
                // Final attempt failed - log so persistent leaks are visible
                Console.Error.WriteLine(
                    $"[TestDirectoryHelper] Failed to delete '{path}' after {maxRetries} attempts: {ex.Message}");
            }
            catch (UnauthorizedAccessException ex)
            {
                // Final attempt failed - log so persistent leaks are visible
                Console.Error.WriteLine(
                    $"[TestDirectoryHelper] Failed to delete '{path}' after {maxRetries} attempts: {ex.Message}");
            }
        }
    }
}
