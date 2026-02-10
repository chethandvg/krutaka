using FluentAssertions;
using Krutaka.Tools;
using System.Security;

namespace Krutaka.Tools.Tests;

public class SecurityPolicyTests
{
    private readonly CommandPolicy _policy;
    private readonly string _projectRoot;

    public SecurityPolicyTests()
    {
        _policy = new CommandPolicy();
        // Use a unique directory that won't be blocked by path validation
        // and won't collide with parallel test runs
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        _projectRoot = Path.Combine(Path.GetTempPath(), $"krutaka-test-{uniqueId}");
        Directory.CreateDirectory(_projectRoot);
    }

    #region Command Validation Tests

    [Theory]
    [InlineData("git")]
    [InlineData("dotnet")]
    [InlineData("node")]
    [InlineData("npm")]
    [InlineData("python")]
    [InlineData("cat")]
    [InlineData("find")]
    [InlineData("grep")]
    public void Should_AllowWhitelistedCommand(string executable)
    {
        // Act
        var action = () => _policy.ValidateCommand(executable, []);

        // Assert
        action.Should().NotThrow();
    }

    [Theory]
    [InlineData("GIT")]
    [InlineData("Dotnet")]
    [InlineData("NODE")]
    [InlineData("Python")]
    public void Should_AllowWhitelistedCommand_CaseInsensitive(string executable)
    {
        // Act
        var action = () => _policy.ValidateCommand(executable, []);

        // Assert
        action.Should().NotThrow();
    }

    [Theory]
    [InlineData("git.exe")]
    [InlineData("dotnet.exe")]
    [InlineData("node.exe")]
    public void Should_AllowWhitelistedCommand_WithExeExtension(string executable)
    {
        // Act
        var action = () => _policy.ValidateCommand(executable, []);

        // Assert
        action.Should().NotThrow();
    }

    [Theory]
    [InlineData("powershell")]
    [InlineData("pwsh")]
    [InlineData("cmd")]
    [InlineData("reg")]
    [InlineData("regedit")]
    [InlineData("netsh")]
    [InlineData("certutil")]
    [InlineData("bitsadmin")]
    [InlineData("format")]
    [InlineData("diskpart")]
    [InlineData("rundll32")]
    [InlineData("regsvr32")]
    [InlineData("mshta")]
    [InlineData("wscript")]
    [InlineData("cscript")]
    [InlineData("msiexec")]
    [InlineData("sc")]
    [InlineData("schtasks")]
    [InlineData("taskkill")]
    [InlineData("net")]
    [InlineData("runas")]
    [InlineData("curl")]
    [InlineData("wget")]
    public void Should_BlockBlacklistedCommand(string executable)
    {
        // Act
        var action = () => _policy.ValidateCommand(executable, []);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage($"Blocked executable: '{executable}'*");
    }

    [Theory]
    [InlineData("POWERSHELL")]
    [InlineData("Cmd")]
    [InlineData("CERTUTIL")]
    public void Should_BlockBlacklistedCommand_CaseInsensitive(string executable)
    {
        // Act
        var action = () => _policy.ValidateCommand(executable, []);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("Blocked executable:*");
    }

    [Fact]
    public void Should_BlockNonWhitelistedCommand()
    {
        // Act
        var action = () => _policy.ValidateCommand("malicious-tool", []);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("Executable 'malicious-tool' is not in the allowlist*");
    }

    [Theory]
    [InlineData("git|ls")]
    [InlineData("git>output.txt")]
    [InlineData("git>>output.txt")]
    [InlineData("git&&ls")]
    [InlineData("git||ls")]
    [InlineData("git;ls")]
    [InlineData("git`ls`")]
    [InlineData("git$(ls)")]
    [InlineData("git%PATH%")]
    [InlineData("git&ls")]
    [InlineData("git<input.txt")]
    [InlineData("git^ls")]
    public void Should_BlockExecutableWithShellMetacharacters(string executable)
    {
        // Act
        var action = () => _policy.ValidateCommand(executable, []);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*shell metacharacters*");
    }

    [Theory]
    [InlineData("status|ls")]
    [InlineData("status>output.txt")]
    [InlineData("status&&rm")]
    [InlineData("status;rm -rf")]
    [InlineData("$(malicious)")]
    [InlineData("%PATH%")]
    public void Should_BlockArgumentWithShellMetacharacters(string argument)
    {
        // Act
        var action = () => _policy.ValidateCommand("git", [argument]);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*shell metacharacters*");
    }

    [Fact]
    public void Should_AllowSafeArguments()
    {
        // Act
        var action = () => _policy.ValidateCommand("git", ["status", "--short"]);

        // Assert
        action.Should().NotThrow();
    }

    [Fact]
    public void Should_ThrowOnEmptyExecutable()
    {
        // Act
        var action = () => _policy.ValidateCommand("", []);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("Executable name cannot be empty*");
    }

    [Fact]
    public void Should_ThrowOnNullExecutable()
    {
        // Act
        var action = () => _policy.ValidateCommand(null!, []);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_ThrowOnNullArguments()
    {
        // Act
        var action = () => _policy.ValidateCommand("git", null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    #endregion

    #region Path Validation Tests

    [Fact]
    public void Should_AllowValidRelativePath()
    {
        // Arrange
        var relativePath = "src/Program.cs";

        // Act
        var result = _policy.ValidatePath(relativePath, _projectRoot);

        // Assert
        result.Should().StartWith(_projectRoot);
        result.Should().Contain("src");
        result.Should().Contain("Program.cs");
    }

    [Fact]
    public void Should_AllowValidAbsolutePath()
    {
        // Arrange
        var absolutePath = Path.Combine(_projectRoot, "src", "Program.cs");

        // Act
        var result = _policy.ValidatePath(absolutePath, _projectRoot);

        // Assert
        result.Should().Be(absolutePath);
    }

    [Theory]
    [InlineData("../../../etc/passwd")]
    [InlineData("src/../../outside.txt")]
    [InlineData("src/../../../etc/shadow")]
    public void Should_BlockPathTraversal(string maliciousPath)
    {
        // Act
        var action = () => _policy.ValidatePath(maliciousPath, _projectRoot);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*path traversal*");
    }

    [Theory]
    [InlineData("C:\\Windows\\System32\\config.sys")]
    [InlineData("C:\\Windows\\notepad.exe")]
    [InlineData("C:\\Program Files\\app\\file.txt")]
    [InlineData("C:\\Program Files (x86)\\tool\\data.dat")]
    public void Should_BlockAccessToSystemDirectories(string blockedPath)
    {
        // Skip on non-Windows (these paths are only meaningful on Windows)
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // Act
        var action = () => _policy.ValidatePath(blockedPath, _projectRoot);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*not permitted*");
    }

    [Fact]
    public void Should_BlockAccessToAppData()
    {
        // Arrange
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        
        // Skip test if AppData path is empty or if it's not a Windows path
        if (string.IsNullOrEmpty(appDataPath) || !appDataPath.Contains("AppData", StringComparison.OrdinalIgnoreCase))
        {
            return; // Test only applies to Windows
        }
        
        var blockedPath = Path.Combine(appDataPath, "test.txt");

        // Act
        var action = () => _policy.ValidatePath(blockedPath, _projectRoot);

        // Assert - Should be blocked (either by path traversal or AppData check)
        action.Should().Throw<SecurityException>();
    }

    [Fact]
    public void Should_BlockAccessToLocalAppData()
    {
        // Arrange
        var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        
        // Skip test if LocalAppData path is empty or if it's not a Windows path
        if (string.IsNullOrEmpty(localAppDataPath) || !localAppDataPath.Contains("AppData", StringComparison.OrdinalIgnoreCase))
        {
            return; // Test only applies to Windows
        }
        
        var blockedPath = Path.Combine(localAppDataPath, "test.txt");

        // Act
        var action = () => _policy.ValidatePath(blockedPath, _projectRoot);

        // Assert - Should be blocked (either by path traversal or AppData check)
        action.Should().Throw<SecurityException>();
    }

    [Fact]
    public void Should_BlockAccessToKrutakaConfigDirectory()
    {
        // Arrange
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var krutakaPath = Path.Combine(userProfile, ".krutaka", "config.json");

        // Act
        var action = () => _policy.ValidatePath(krutakaPath, _projectRoot);

        // Assert - This should be blocked, either by path traversal or by explicit Krutaka directory check
        action.Should().Throw<SecurityException>();
    }

    [Theory]
    [InlineData(".env")]
    [InlineData(".env.local")]
    [InlineData(".env.production")]
    [InlineData(".credentials")]
    [InlineData(".secret")]
    [InlineData(".secrets")]
    public void Should_BlockSensitiveConfigFiles(string fileName)
    {
        // Arrange
        var blockedPath = Path.Combine(_projectRoot, fileName);

        // Act
        var action = () => _policy.ValidatePath(blockedPath, _projectRoot);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*not permitted*");
    }

    [Theory]
    [InlineData("certificate.pfx")]
    [InlineData("certificate.p12")]
    [InlineData("private.key")]
    [InlineData("cert.pem")]
    [InlineData("cert.cer")]
    [InlineData("cert.crt")]
    [InlineData("passwords.kdbx")]
    public void Should_BlockCertificateAndKeyFiles(string fileName)
    {
        // Arrange
        var blockedPath = Path.Combine(_projectRoot, fileName);

        // Act
        var action = () => _policy.ValidatePath(blockedPath, _projectRoot);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*not permitted*");
    }

    [Theory]
    [InlineData("id_rsa")]
    [InlineData("id_rsa.pub")]
    [InlineData("id_ed25519")]
    [InlineData("id_ed25519.pub")]
    [InlineData("known_hosts")]
    [InlineData("authorized_keys")]
    public void Should_BlockSSHKeyFiles(string fileName)
    {
        // Arrange
        var blockedPath = Path.Combine(_projectRoot, fileName);

        // Act
        var action = () => _policy.ValidatePath(blockedPath, _projectRoot);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*not permitted*");
    }

    [Theory]
    [InlineData("\\\\server\\share\\file.txt")]
    [InlineData("//server/share/file.txt")]
    public void Should_BlockUNCPaths(string uncPath)
    {
        // Act
        var action = () => _policy.ValidatePath(uncPath, _projectRoot);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("*UNC paths*not permitted*");
    }

    [Fact]
    public void Should_ThrowOnEmptyPath()
    {
        // Act
        var action = () => _policy.ValidatePath("", _projectRoot);

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("Path cannot be empty*");
    }

    [Fact]
    public void Should_ThrowOnNullPath()
    {
        // Act
        var action = () => _policy.ValidatePath(null!, _projectRoot);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_ThrowOnEmptyAllowedRoot()
    {
        // Act
        var action = () => _policy.ValidatePath("test.txt", "");

        // Assert
        action.Should().Throw<SecurityException>()
            .WithMessage("Allowed root cannot be empty*");
    }

    #endregion

    #region Environment Scrubbing Tests

    [Fact]
    public void Should_RemoveApiKeyVariables()
    {
        // Arrange
        var environment = new Dictionary<string, string?>
        {
            ["ANTHROPIC_API_KEY"] = "sk-ant-test123",
            ["MY_API_KEY"] = "secret",
            ["NORMAL_VAR"] = "value"
        };

        // Act
        var result = _policy.ScrubEnvironment(environment);

        // Assert
        result.Should().NotContainKey("ANTHROPIC_API_KEY");
        result.Should().NotContainKey("MY_API_KEY");
        result.Should().ContainKey("NORMAL_VAR");
    }

    [Fact]
    public void Should_RemoveSecretVariables()
    {
        // Arrange
        var environment = new Dictionary<string, string?>
        {
            ["DATABASE_SECRET"] = "db-secret",
            ["APP_SECRET"] = "app-secret",
            ["NORMAL_VAR"] = "value"
        };

        // Act
        var result = _policy.ScrubEnvironment(environment);

        // Assert
        result.Should().NotContainKey("DATABASE_SECRET");
        result.Should().NotContainKey("APP_SECRET");
        result.Should().ContainKey("NORMAL_VAR");
    }

    [Fact]
    public void Should_RemoveTokenVariables()
    {
        // Arrange
        var environment = new Dictionary<string, string?>
        {
            ["GITHUB_TOKEN"] = "ghp_test",
            ["AUTH_TOKEN"] = "bearer-token",
            ["NORMAL_VAR"] = "value"
        };

        // Act
        var result = _policy.ScrubEnvironment(environment);

        // Assert
        result.Should().NotContainKey("GITHUB_TOKEN");
        result.Should().NotContainKey("AUTH_TOKEN");
        result.Should().ContainKey("NORMAL_VAR");
    }

    [Fact]
    public void Should_RemovePasswordVariables()
    {
        // Arrange
        var environment = new Dictionary<string, string?>
        {
            ["DB_PASSWORD"] = "password123",
            ["ADMIN_PASSWORD"] = "admin123",
            ["NORMAL_VAR"] = "value"
        };

        // Act
        var result = _policy.ScrubEnvironment(environment);

        // Assert
        result.Should().NotContainKey("DB_PASSWORD");
        result.Should().NotContainKey("ADMIN_PASSWORD");
        result.Should().ContainKey("NORMAL_VAR");
    }

    [Fact]
    public void Should_RemoveAnthropicVariables()
    {
        // Arrange
        var environment = new Dictionary<string, string?>
        {
            ["ANTHROPIC_API_KEY"] = "sk-ant-test",
            ["ANTHROPIC_BASE_URL"] = "https://api.anthropic.com",
            ["NORMAL_VAR"] = "value"
        };

        // Act
        var result = _policy.ScrubEnvironment(environment);

        // Assert
        result.Should().NotContainKey("ANTHROPIC_API_KEY");
        result.Should().NotContainKey("ANTHROPIC_BASE_URL");
        result.Should().ContainKey("NORMAL_VAR");
    }

    [Fact]
    public void Should_RemoveCloudProviderVariables()
    {
        // Arrange
        var environment = new Dictionary<string, string?>
        {
            ["AWS_ACCESS_KEY_ID"] = "AKIA...",
            ["AWS_SECRET_ACCESS_KEY"] = "secret",
            ["AZURE_SUBSCRIPTION_ID"] = "guid",
            ["GCP_PROJECT_ID"] = "project-123",
            ["GOOGLE_APPLICATION_CREDENTIALS"] = "/path/to/creds.json",
            ["NORMAL_VAR"] = "value"
        };

        // Act
        var result = _policy.ScrubEnvironment(environment);

        // Assert
        result.Should().NotContainKey("AWS_ACCESS_KEY_ID");
        result.Should().NotContainKey("AWS_SECRET_ACCESS_KEY");
        result.Should().NotContainKey("AZURE_SUBSCRIPTION_ID");
        result.Should().NotContainKey("GCP_PROJECT_ID");
        result.Should().NotContainKey("GOOGLE_APPLICATION_CREDENTIALS");
        result.Should().ContainKey("NORMAL_VAR");
    }

    [Fact]
    public void Should_BeCaseInsensitive()
    {
        // Arrange
        var environment = new Dictionary<string, string?>
        {
            ["api_key"] = "secret",
            ["API_SECRET"] = "secret",
            ["Auth_Token"] = "token",
            ["normal_var"] = "value"
        };

        // Act
        var result = _policy.ScrubEnvironment(environment);

        // Assert
        result.Should().NotContainKey("api_key");
        result.Should().NotContainKey("API_SECRET");
        result.Should().NotContainKey("Auth_Token");
        result.Should().ContainKey("normal_var");
    }

    [Fact]
    public void Should_PreserveNormalVariables()
    {
        // Arrange
        var environment = new Dictionary<string, string?>
        {
            ["PATH"] = "/usr/bin",
            ["HOME"] = "/home/user",
            ["USER"] = "testuser",
            ["TEMP"] = "/tmp"
        };

        // Act
        var result = _policy.ScrubEnvironment(environment);

        // Assert
        result.Should().HaveCount(4);
        result.Should().ContainKeys("PATH", "HOME", "USER", "TEMP");
    }

    [Fact]
    public void Should_HandleEmptyEnvironment()
    {
        // Arrange
        var environment = new Dictionary<string, string?>();

        // Act
        var result = _policy.ScrubEnvironment(environment);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void Should_ThrowOnNullEnvironment()
    {
        // Act
        var action = () => _policy.ScrubEnvironment(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    #endregion

    #region Approval Required Tests

    [Theory]
    [InlineData("write_file")]
    [InlineData("edit_file")]
    [InlineData("run_command")]
    public void Should_RequireApprovalForHighRiskTools(string toolName)
    {
        // Act
        var result = _policy.IsApprovalRequired(toolName);

        // Assert
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("WRITE_FILE")]
    [InlineData("Edit_File")]
    [InlineData("RUN_COMMAND")]
    public void Should_RequireApprovalForHighRiskTools_CaseInsensitive(string toolName)
    {
        // Act
        var result = _policy.IsApprovalRequired(toolName);

        // Assert
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData("read_file")]
    [InlineData("list_files")]
    [InlineData("search_files")]
    [InlineData("memory_store")]
    [InlineData("memory_search")]
    public void Should_NotRequireApprovalForLowRiskTools(string toolName)
    {
        // Act
        var result = _policy.IsApprovalRequired(toolName);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void Should_ThrowOnNullToolName()
    {
        // Act
        var action = () => _policy.IsApprovalRequired(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    #endregion

    #region SafeFileOperations Tests

    [Fact]
    public void Should_ValidateFileSizeLimit()
    {
        // Arrange
        var testFile = Path.Combine(_projectRoot, "test.txt");
        Directory.CreateDirectory(_projectRoot);
        
        // Create a file larger than 1MB
        var largeContent = new string('x', (int)SafeFileOperations.MaxFileSizeBytes + 1);
        File.WriteAllText(testFile, largeContent);

        try
        {
            // Act
            var action = () => SafeFileOperations.ValidateFileSize(testFile);

            // Assert
            action.Should().Throw<SecurityException>()
                .WithMessage("*exceeds maximum allowed size*");
        }
        finally
        {
            // Cleanup
            if (File.Exists(testFile))
            {
                File.Delete(testFile);
            }
        }
    }

    [Fact]
    public void Should_AllowFilesUnderSizeLimit()
    {
        // Arrange
        var testFile = Path.Combine(_projectRoot, "small.txt");
        Directory.CreateDirectory(_projectRoot);
        File.WriteAllText(testFile, "small content");

        try
        {
            // Act
            var action = () => SafeFileOperations.ValidateFileSize(testFile);

            // Assert
            action.Should().NotThrow();
        }
        finally
        {
            // Cleanup
            if (File.Exists(testFile))
            {
                File.Delete(testFile);
            }
        }
    }

    [Fact]
    public void Should_AllowNonExistentFiles()
    {
        // Arrange
        var nonExistentFile = Path.Combine(_projectRoot, "nonexistent.txt");

        // Act
        var action = () => SafeFileOperations.ValidateFileSize(nonExistentFile);

        // Assert
        action.Should().NotThrow();
    }

    #endregion
}
