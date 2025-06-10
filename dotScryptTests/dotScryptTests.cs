using nebulae.dotScrypt;
using System.Text;

namespace dotScryptTests;

public class dotScryptTests
{
    // Make sure we've got a good version of the native library loaded
    [Fact]
    public void Scrypt_DoesNotCrash()
    {
        Scrypt.Init();

        byte[] password = System.Text.Encoding.UTF8.GetBytes("test123");
        byte[] salt = new byte[16];
        byte[] output = new byte[64];

        var result = Scrypt.Hash(password, salt, 16384, 8, 1, output);

        Assert.Equal(0, result); // 0 = success
    }

    // Test that the output buffer is filled with non-zero values
    [Fact]
    public void Scrypt_OutputIsNonZero()
    {
        Scrypt.Init();

        byte[] password = System.Text.Encoding.UTF8.GetBytes("hunter2");
        byte[] salt = new byte[16];
        new Random(42).NextBytes(salt);

        byte[] output = new byte[64];
        var result = Scrypt.Hash(password, salt, 16384, 8, 1, output);

        Assert.Equal(0, result);
        Assert.Contains(output, b => b != 0);
    }

    // Tests that the output matches a known RFC vector
    [Fact]
    public void Scrypt_RFCVector_MatchesExpected()
    {
        Scrypt.Init();

        byte[] password = Encoding.UTF8.GetBytes("password");
        byte[] salt = Encoding.UTF8.GetBytes("NaCl");
        byte[] output = new byte[64];

        int result = Scrypt.Hash(password, salt, 1024, 8, 16, output);

        Assert.Equal(0, result);

        string actualHex = BitConverter.ToString(output).Replace("-", "").ToLowerInvariant();
        string expectedHex =
            "fdbabe1c9d3472007856e7190d01e9fe" +
            "7c6ad7cbc8237830e77376634b373162" +
            "2eaf30d92e22a3886ff109279d9830da" +
            "c727afb94a83ee6d8360cbdfa2cc0640";

        Assert.Equal(expectedHex, actualHex);
    }

    // Test that our encoding function produces the expected output
    [Fact]
    public void Encode_ProducesExpectedEncodedOutput()
    {
        string password = "test123";
        byte[] salt = Convert.FromBase64String("w7qv9FVm6BqK0TQsmzayLQ=="); // 16 bytes

        ulong N = 16384;
        uint r = 8;
        uint p = 1;
        int hashLength = 64;

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] output = new byte[hashLength];

        Scrypt.Hash(
            passwordBytes,
            salt,
            N,
            r,
            p,
            output
        );

        string expectedEncoded = "$scrypt$N=16384$r=8$p=1$salt=w7qv9FVm6BqK0TQsmzayLQ==$hash=" + Convert.ToBase64String(output);
        string actualEncoded = Scrypt.EncodeHash(output, salt, N, r, p);

        Assert.Equal(expectedEncoded, actualEncoded);
    }

    // Test that our hashing and encoding survives roundtrip
    [Fact]
    public void Roundtrip_Success()
    {
        string password = "correct horse battery staple";

        string hash = Scrypt.HashPassword(
            password,
            hashLength: 64,
            saltLength: 16,
            N: 131072,
            r: 8,
            p: 1
        );

        Assert.True(Scrypt.Verify(password, hash));
    }

    // Test that verification fails with a wrong password
    [Fact]
    public void Roundtrip_Failure()
    {
        string password = "correct horse battery staple";
        string wrongPassword = "tr0ub4dor&3";

        string hash = Scrypt.HashPassword(
            password,
            hashLength: 64,
            saltLength: 16,
            N: 131072,
            r: 8,
            p: 1
        );

        Assert.False(Scrypt.Verify(wrongPassword, hash));
    }

    // Make sure we throw on malformed encoded hashes
    [Fact]
    public void Verify_ThrowsOnMalformedInput()
    {
        Assert.Throws<FormatException>(() =>
        {
            Scrypt.Verify("password123", "$scrypt$bad$input");
        });
    }
}