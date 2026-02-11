using FluentAssertions;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

public sealed class EnvironmentScrubberTests
{
    [Fact]
    public void Should_RemoveAnthropicPrefixedVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["ANTHROPIC_API_KEY"] = "sk-ant-test",
            ["PATH"] = "/usr/bin"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("ANTHROPIC_API_KEY");
        result.Should().ContainKey("PATH");
    }

    [Fact]
    public void Should_RemoveAwsPrefixedVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["AWS_ACCESS_KEY_ID"] = "AKIA...",
            ["AWS_SECRET_ACCESS_KEY"] = "secret",
            ["HOME"] = "/home/user"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("AWS_ACCESS_KEY_ID");
        result.Should().NotContainKey("AWS_SECRET_ACCESS_KEY");
        result.Should().ContainKey("HOME");
    }

    [Fact]
    public void Should_RemoveAzurePrefixedVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["AZURE_CLIENT_ID"] = "client-id",
            ["AZURE_TENANT_ID"] = "tenant-id",
            ["TERM"] = "xterm"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("AZURE_CLIENT_ID");
        result.Should().NotContainKey("AZURE_TENANT_ID");
        result.Should().ContainKey("TERM");
    }

    [Fact]
    public void Should_RemoveGcpAndGooglePrefixedVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["GCP_PROJECT"] = "my-project",
            ["GOOGLE_APPLICATION_CREDENTIALS"] = "/path/to/creds.json",
            ["LANG"] = "en_US.UTF-8"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("GCP_PROJECT");
        result.Should().NotContainKey("GOOGLE_APPLICATION_CREDENTIALS");
        result.Should().ContainKey("LANG");
    }

    [Fact]
    public void Should_RemoveGitHubPrefixedVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["GITHUB_TOKEN"] = "ghp_test123",
            ["GITHUB_ACTIONS"] = "true",
            ["SHELL"] = "/bin/bash"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("GITHUB_TOKEN");
        result.Should().NotContainKey("GITHUB_ACTIONS");
        result.Should().ContainKey("SHELL");
    }

    [Fact]
    public void Should_RemoveGitLabPrefixedVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["GITLAB_TOKEN"] = "glpat-test",
            ["GITLAB_CI"] = "true",
            ["USER"] = "developer"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("GITLAB_TOKEN");
        result.Should().NotContainKey("GITLAB_CI");
        result.Should().ContainKey("USER");
    }

    [Fact]
    public void Should_RemoveOpenAIPrefixedVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["OPENAI_API_KEY"] = "sk-test",
            ["PATH"] = "/usr/bin"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("OPENAI_API_KEY");
        result.Should().ContainKey("PATH");
    }

    [Fact]
    public void Should_RemoveHuggingFacePrefixedVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["HUGGINGFACE_TOKEN"] = "hf_test",
            ["PATH"] = "/usr/bin"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("HUGGINGFACE_TOKEN");
        result.Should().ContainKey("PATH");
    }

    [Fact]
    public void Should_RemoveSuffixMatchedVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["MY_API_KEY"] = "key123",
            ["DB_SECRET"] = "secret456",
            ["AUTH_TOKEN"] = "token789",
            ["DB_PASSWORD"] = "pass000",
            ["SERVICE_CREDENTIAL"] = "cred123",
            ["GOOGLE_APPLICATION_CREDENTIALS"] = "/path/to/creds.json",
            ["HOME"] = "/home/user"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("MY_API_KEY");
        result.Should().NotContainKey("DB_SECRET");
        result.Should().NotContainKey("AUTH_TOKEN");
        result.Should().NotContainKey("DB_PASSWORD");
        result.Should().NotContainKey("SERVICE_CREDENTIAL");
        result.Should().NotContainKey("GOOGLE_APPLICATION_CREDENTIALS");
        result.Should().ContainKey("HOME");
    }

    [Fact]
    public void Should_BeCaseInsensitiveForSuffixes()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["my_api_key"] = "key123",
            ["Db_Secret"] = "secret456",
            ["PATH"] = "/usr/bin"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("my_api_key");
        result.Should().NotContainKey("Db_Secret");
        result.Should().ContainKey("PATH");
    }

    [Fact]
    public void Should_BeCaseInsensitiveForPrefixes()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["anthropic_api_key"] = "sk-ant-test",
            ["Aws_Region"] = "us-east-1",
            ["TERM"] = "xterm"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().NotContainKey("anthropic_api_key");
        result.Should().NotContainKey("Aws_Region");
        result.Should().ContainKey("TERM");
    }

    [Fact]
    public void Should_PreserveSafeVariables()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["PATH"] = "/usr/bin",
            ["HOME"] = "/home/user",
            ["LANG"] = "en_US.UTF-8",
            ["TERM"] = "xterm",
            ["SHELL"] = "/bin/bash",
            ["USER"] = "developer"
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().HaveCount(6);
        result.Should().ContainKey("PATH");
        result.Should().ContainKey("HOME");
        result.Should().ContainKey("LANG");
        result.Should().ContainKey("TERM");
        result.Should().ContainKey("SHELL");
        result.Should().ContainKey("USER");
    }

    [Fact]
    public void Should_HandleEmptyDictionary()
    {
        // Arrange
        var env = new Dictionary<string, string?>();

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void Should_ThrowOnNullInput()
    {
        // Act
        var act = () => EnvironmentScrubber.ScrubEnvironment(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_HandleVariablesWithNullValues()
    {
        // Arrange
        var env = new Dictionary<string, string?>
        {
            ["PATH"] = null,
            ["ANTHROPIC_KEY"] = null
        };

        // Act
        var result = EnvironmentScrubber.ScrubEnvironment(env);

        // Assert
        result.Should().ContainKey("PATH");
        result.Should().NotContainKey("ANTHROPIC_KEY");
    }
}
