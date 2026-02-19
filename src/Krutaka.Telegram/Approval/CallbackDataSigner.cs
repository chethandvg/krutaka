using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;

namespace Krutaka.Telegram;

/// <summary>
/// Utility class for signing and verifying inline keyboard callback payloads using HMAC-SHA256.
/// Prevents tampering, replay attacks, and cross-user approval.
/// Works with compact payloads (approval ID only) to stay under Telegram's 64-byte limit.
/// </summary>
public sealed class CallbackDataSigner
{
    private readonly byte[] _secret;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

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
    /// Result is kept under 64 bytes for Telegram's callback_data limit.
    /// </summary>
    /// <param name="payload">The callback payload to sign (Hmac field is ignored).</param>
    /// <returns>JSON string with the payload and HMAC signature (under 64 bytes).</returns>
    public string Sign(CallbackPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        // Compute HMAC of just the approval ID
        var hmac = ComputeHmac(payload.ApprovalId);

        // Create signed payload
        var signedPayload = payload with { Hmac = hmac };

        // Serialize to compact JSON
        return JsonSerializer.Serialize(signedPayload, JsonOptions);
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
            var payload = JsonSerializer.Deserialize<CallbackPayload>(data, JsonOptions);

            if (payload == null || string.IsNullOrWhiteSpace(payload.Hmac))
            {
                return null;
            }

            // Compute expected HMAC
            var expectedHmac = ComputeHmac(payload.ApprovalId);

            // Constant-time comparison using framework-provided method
            var expectedBytes = Convert.FromBase64String(expectedHmac);
            var actualBytes = Convert.FromBase64String(payload.Hmac);
            
            if (!CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes))
            {
                return null;
            }

            return payload;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (FormatException)
        {
            // Invalid Base64 in HMAC
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
}
