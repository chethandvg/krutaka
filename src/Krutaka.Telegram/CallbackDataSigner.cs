using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Krutaka.Telegram;

/// <summary>
/// Utility class for signing and verifying inline keyboard callback payloads using HMAC-SHA256.
/// Prevents tampering, replay attacks, and cross-user approval.
/// </summary>
public sealed class CallbackDataSigner
{
    private readonly byte[] _secret;

    /// <summary>
    /// Initializes a new instance of the <see cref="CallbackDataSigner"/> class.
    /// </summary>
    /// <param name="secret">The HMAC secret key (should be 32 bytes from RandomNumberGenerator).</param>
    public CallbackDataSigner(byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length < 32)
        {
            throw new ArgumentException("Secret must be at least 32 bytes.", nameof(secret));
        }

        _secret = secret;
    }

    /// <summary>
    /// Signs a callback payload and returns the serialized JSON with HMAC signature.
    /// </summary>
    /// <param name="payload">The callback payload to sign (Hmac field is ignored).</param>
    /// <returns>JSON string with the payload and HMAC signature.</returns>
    public string Sign(CallbackPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        // Create a payload without HMAC for signing
        var unsignedPayload = payload with { Hmac = null };

        // Serialize to JSON (canonical format for signing)
        var jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        var unsignedJson = JsonSerializer.Serialize(unsignedPayload, jsonOptions);

        // Compute HMAC-SHA256
        var hmac = ComputeHmac(unsignedJson);

        // Create signed payload
        var signedPayload = payload with { Hmac = hmac };

        // Return serialized signed payload
        return JsonSerializer.Serialize(signedPayload, jsonOptions);
    }

    /// <summary>
    /// Verifies a callback data string and returns the payload if valid, or null if tampered.
    /// </summary>
    /// <param name="data">The serialized callback data (JSON with HMAC).</param>
    /// <returns>The validated payload if HMAC is correct, otherwise null.</returns>
    public CallbackPayload? Verify(string data)
    {
        if (string.IsNullOrWhiteSpace(data))
        {
            return null;
        }

        try
        {
            // Deserialize the payload
            var jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
            var payload = JsonSerializer.Deserialize<CallbackPayload>(data, jsonOptions);

            if (payload == null || string.IsNullOrWhiteSpace(payload.Hmac))
            {
                return null;
            }

            // Recreate unsigned payload for verification
            var unsignedPayload = payload with { Hmac = null };
            var unsignedJson = JsonSerializer.Serialize(unsignedPayload, jsonOptions);

            // Compute expected HMAC
            var expectedHmac = ComputeHmac(unsignedJson);

            // Constant-time comparison to prevent timing attacks
            if (!ConstantTimeEquals(expectedHmac, payload.Hmac))
            {
                return null;
            }

            return payload;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Computes HMAC-SHA256 for the given data.
    /// </summary>
    private string ComputeHmac(string data)
    {
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var hashBytes = HMACSHA256.HashData(_secret, dataBytes);
        return Convert.ToBase64String(hashBytes);
    }

    /// <summary>
    /// Constant-time string comparison to prevent timing attacks.
    /// </summary>
    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length)
        {
            return false;
        }

        var result = 0;
        for (var i = 0; i < a.Length; i++)
        {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }
}
