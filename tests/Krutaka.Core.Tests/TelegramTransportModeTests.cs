using FluentAssertions;

namespace Krutaka.Core.Tests;

public class TelegramTransportModeTests
{
    [Fact]
    public void Enum_Should_HaveLongPollingValue()
    {
        // Act & Assert
        TelegramTransportMode.LongPolling.Should().BeDefined();
        ((int)TelegramTransportMode.LongPolling).Should().Be(0);
    }

    [Fact]
    public void Enum_Should_HaveWebhookValue()
    {
        // Act & Assert
        TelegramTransportMode.Webhook.Should().BeDefined();
        ((int)TelegramTransportMode.Webhook).Should().Be(1);
    }

    [Fact]
    public void Enum_Should_OnlyHaveTwoValues()
    {
        // Act
        var values = Enum.GetValues<TelegramTransportMode>();

        // Assert
        values.Should().HaveCount(2);
        values.Should().Contain(TelegramTransportMode.LongPolling);
        values.Should().Contain(TelegramTransportMode.Webhook);
    }
}
