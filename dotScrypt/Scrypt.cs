using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace nebulae.dotScrypt;

public static class Scrypt
{
    /// <summary>
    /// Initializes the underlying native library and prepares it for use.
    /// </summary>
    /// <remarks>This method must be called before using any functionality that depends on the native library.
    /// Failure to call this method may result in undefined behavior or runtime errors.</remarks>
    public static void Init()
    {
        NativeMethods.Init();
    }

    /// <summary>
    /// Computes a cryptographic hash of the specified password using the scrypt key derivation function.
    /// </summary>
    /// <remarks>This method uses the scrypt key derivation function, which is designed to be computationally
    /// intensive and memory-hard. It is suitable for securely hashing passwords to protect against brute-force attacks.
    /// Ensure that the parameters <paramref name="N"/>, <paramref name="r"/>, and <paramref name="p"/> are chosen
    /// carefully to balance security and performance.</remarks>
    /// <param name="password">The password to be hashed, represented as a byte array. Cannot be null or empty.</param>
    /// <param name="salt">The cryptographic salt to use for hashing, represented as a byte array. Cannot be null or empty.</param>
    /// <param name="N">The CPU/memory cost parameter, which must be a power of two. Higher values increase computational cost.</param>
    /// <param name="r">The block size parameter, which affects memory usage and parallelism. Must be greater than zero.</param>
    /// <param name="p">The parallelization parameter, which affects the number of independent computations. Must be greater than zero.</param>
    /// <param name="output">The buffer to store the resulting hash, represented as a byte array. Must be pre-allocated and large enough to
    /// hold the hash.</param>
    /// <returns>An integer indicating the result of the hashing operation. A value of 0 typically indicates success, while
    /// non-zero values may indicate an error.</returns>
    public static int Hash(
        byte[] password, byte[] salt,
        ulong N, uint r, uint p,
        byte[] output)
    {
        Init();

        return NativeMethods.scrypt_kdf(
            password, (UIntPtr)password.Length,
            salt, (UIntPtr)salt.Length,
            N, r, p,
            output, (UIntPtr)output.Length);
    }

    /// <summary>
    /// Generates a secure hash for the specified password using the scrypt key derivation function.
    /// </summary>
    /// <remarks>This method uses the scrypt key derivation function to generate a secure hash for the
    /// password. The resulting hash includes the scrypt parameters, salt, and hash, encoded in a standardized format.
    /// The caller is responsible for securely storing the returned hash for future password verification.</remarks>
    /// <param name="password">The password to be hashed. Cannot be null or empty.</param>
    /// <param name="hashLength">The desired length of the resulting hash, in bytes. Must be greater than zero. Defaults to 64.</param>
    /// <param name="saltLength">The length of the salt, in bytes. Must be greater than zero. Defaults to 16.</param>
    /// <param name="N">The CPU/memory cost parameter for the scrypt algorithm. Must be a power of 2. Defaults to 131072 (2^17 in line 
    /// with OWASP recommendations as of June 2025).</param>
    /// <param name="r">The block size parameter for the scrypt algorithm. Must be greater than zero. Defaults to 8 (in line with
    /// OWASP recommendations as of June 2025).</param>
    /// <param name="p">The parallelization parameter for the scrypt algorithm. Must be greater than zero. Defaults to 1 (in line
    /// with OWASP recommendations as of June 2025).</param>
    /// <returns>A string containing the hashed password in a format that includes the scrypt parameters, salt, and hash. The
    /// format is: <c>$scrypt$N={N}$r={r}$p={p}$salt={salt}$hash={hash}</c>.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the underlying scrypt key derivation function fails.</exception>
    public static string HashPassword(
        string password,
        int hashLength = 64,
        int saltLength = 16,
        ulong N = 131072,
        uint r = 8,
        uint p = 1)
    {
        NativeMethods.Init();

        var salt = new byte[saltLength];
        RandomNumberGenerator.Fill(salt);

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var output = new byte[hashLength];

        int result = NativeMethods.scrypt_kdf(
            passwordBytes, (UIntPtr)passwordBytes.Length,
            salt, (UIntPtr)salt.Length,
            N, r, p,
            output, (UIntPtr)hashLength
        );

        if (result != 0)
            throw new InvalidOperationException("scrypt_kdf failed");

        return EncodeHash(output, salt, N, r, p);
    }

    public static string EncodeHash(
        byte[] hash,
        byte[] salt,
        ulong N,
        uint r,
        uint p)
    {
        string encodedSalt = Convert.ToBase64String(salt);
        string encodedHash = Convert.ToBase64String(hash);

        return $"$scrypt$N={N}$r={r}$p={p}$salt={encodedSalt}$hash={encodedHash}";
    }

    /// <summary>
    /// Verifies whether the provided password matches the given encoded scrypt hash.
    /// </summary>
    /// <remarks>This method uses the scrypt key derivation function (KDF) to compute a hash of the provided
    /// password and compares it to the expected hash in the encoded string. The comparison is performed in constant
    /// time to mitigate timing attacks.</remarks>
    /// <param name="password">The plaintext password to verify.</param>
    /// <param name="encoded">The encoded scrypt hash to compare against. The format must include the parameters (N, r, p), the salt, and the
    /// expected hash.</param>
    /// <returns><see langword="true"/> if the password matches the encoded hash; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="FormatException">Thrown if the <paramref name="encoded"/> string is not in a valid scrypt hash format.</exception>
    public static bool Verify(string password, string encoded)
    {
        NativeMethods.Init();

        if (!TryParse(encoded, out var N, out var r, out var p, out var salt, out var expectedHash))
            throw new FormatException("Invalid scrypt hash format");

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var output = new byte[expectedHash.Length];

        int result = NativeMethods.scrypt_kdf(
            passwordBytes, (UIntPtr)passwordBytes.Length,
            salt, (UIntPtr)salt.Length,
            N, r, p,
            output, (UIntPtr)output.Length
        );

        if (result != 0)
            return false;

        return CryptographicOperations.FixedTimeEquals(output, expectedHash);
    }

    // internal helper method to parse the encoded scrypt hash string
    private static bool TryParse(string encoded, out ulong N, out uint r, out uint p, out byte[] salt, out byte[] hash)
    {
        N = 0; r = 0; p = 0;
        salt = Array.Empty<byte>();
        hash = Array.Empty<byte>();

        if (string.IsNullOrWhiteSpace(encoded) || !encoded.StartsWith("$scrypt$"))
            return false;

        // Format: $scrypt$N=...$r=...$p=...$salt=...$hash=...
        var parts = encoded.Split('$');

        if (parts.Length != 7 || parts[1] != "scrypt")
            return false;

        try
        {
            N = ulong.Parse(parts[2].Split('=')[1]);
            r = uint.Parse(parts[3].Split('=')[1]);
            p = uint.Parse(parts[4].Split('=')[1]);

            string saltField = parts[5];
            string hashField = parts[6];

            const string saltPrefix = "salt=";
            const string hashPrefix = "hash=";

            if (!saltField.StartsWith(saltPrefix) || !hashField.StartsWith(hashPrefix))
                return false;

            string saltB64 = saltField.Substring(saltPrefix.Length);
            string hashB64 = hashField.Substring(hashPrefix.Length);

            salt = Convert.FromBase64String(saltB64);
            hash = Convert.FromBase64String(hashB64);

            return true;
        }
        catch
        {
            return false;
        }
    }
}
