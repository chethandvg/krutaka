namespace Krutaka.Skills.Tests;

/// <summary>
/// Helper class for creating test directories that work in both local development
/// and CI environments. On Windows CI runners, Path.GetTempPath() returns a path 
/// in LocalAppData which may cause issues with security policy validation.
/// This helper uses an alternative path that's safe for testing.
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
            // Use C:\temp instead of user's temp folder (which is in AppData/Local)
            // This avoids triggering the LocalAppData security check
            var basePath = @"C:\temp";
            
            // Ensure the base directory exists
            if (!Directory.Exists(basePath))
            {
                Directory.CreateDirectory(basePath);
            }
            
            return Path.Combine(basePath, $"krutaka-{testName}-{uniqueId}");
        }
        else
        {
            // On Linux/Mac, /tmp is standard and not restricted
            return Path.Combine("/tmp", $"krutaka-{testName}-{uniqueId}");
        }
    }

    /// <summary>
    /// Safely deletes a test directory with retry logic for file locks.
    /// </summary>
    /// <param name="path">The directory path to delete.</param>
    /// <param name="maxRetries">Maximum number of retry attempts.</param>
    public static void TryDeleteDirectory(string path, int maxRetries = 3)
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
                // Wait a bit before retrying to allow file handles to be released
                Thread.Sleep(100);
            }
            catch (IOException)
            {
                // Final attempt failed - ignore cleanup failures
                // Test directories will be cleaned up eventually
            }
        }
    }
}
