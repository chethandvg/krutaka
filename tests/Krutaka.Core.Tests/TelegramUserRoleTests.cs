using FluentAssertions;

namespace Krutaka.Core.Tests;

public class TelegramUserRoleTests
{
    [Fact]
    public void Enum_Should_HaveUserValue()
    {
        // Act & Assert
        TelegramUserRole.User.Should().BeDefined();
        ((int)TelegramUserRole.User).Should().Be(0);
    }

    [Fact]
    public void Enum_Should_HaveAdminValue()
    {
        // Act & Assert
        TelegramUserRole.Admin.Should().BeDefined();
        ((int)TelegramUserRole.Admin).Should().Be(1);
    }

    [Fact]
    public void Enum_Should_OnlyHaveTwoValues()
    {
        // Act
        var values = Enum.GetValues<TelegramUserRole>();

        // Assert
        values.Should().HaveCount(2);
        values.Should().Contain(TelegramUserRole.User);
        values.Should().Contain(TelegramUserRole.Admin);
    }
}
