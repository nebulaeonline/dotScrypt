# dotScrypt

dotScrypt is a high-performance .NET wrapper for Colin Percival’s reference scrypt key derivation function, built for security, portability, and full parameter control. 

This library provides native, optimized builds for Windows, Linux, and macOS (including Apple Silicon) with zero external dependencies. 

dotScrypt enables direct access to scrypt_kdf() via Scrypt.Hash() through an idiomatic .NET interface, making it ideal for password hashing and cryptographic key derivation in AOT-compatible applications. Additional ergonomic wrappers have been added to: (1) encode the kdf parameters, salt, & password hash; and (2) verify those hashes against a supplied password.

---

## Features

- Supports scrypt_kdf() for secure hashing
- Exposes both raw byte output and encoded string output
- Full control over all parameters: memory & time cost, block size & parallelization (nothing is hidden away or hard-coded, so you can follow OWASP recommendations)
- Cross-platform support: **Windows**, **Linux**, **macOS** (including Apple Silicon)
- Ships with native, optimized builds of the scrypt kdf function: `.dll`, `.so`, `.dylib`
- Built against the **SIMD-optimized** version of the Scrypt reference implementation
- Requires AES-NI & SSE3 instructions sets on (x86_64 only)

---

## Requirements

- .NET 8.0 or later
- AES-NI & SSE3 capable CPU
- Windows x64, Linux x64, or macOS x64/arm64

---

## Usage

For general usage, it is recommended to use the encoded string output for password hashing. If you do so you can use the built-in verification functions. Otherwise, you must re-compute the hash using the same original settings and compare the raw hashes yourself. 

Scrypt.HashPassword() defaults to the current OWASP recommended parameters, but you can override any and all parameters as needed. 

The following example demonstrates how to hash a password and verify it:

```csharp

using nebulae.dotScrypt;

// Hash the password with full parameter control
string encoded = Scrypt.HashPassword(
    password: "correct horse battery staple",
    hashLength: 64,
    saltLength: 16,
    N: 131072,          // CPU/memory cost (2^17)
    r: 8,               // block size
    p: 1                // parallelism
);

// Store `encoded` in your database

// Later, verify a login attempt
bool isValid = Scrypt.Verify("correct horse battery staple", encoded);

Console.WriteLine(isValid ? "Password is valid" : "Invalid password");

```

## Installation

You can install the package via NuGet:

```bash

$ dotnet add package nebulae.dotScrypt

```

Or via git:

```bash

$ git clone https://github.com/nebulaeonline/dotScrypt.git
$ cd dotScrypt
$ dotnet build

```

---

## License

MIT

## Roadmap

The library is feature complete and stable, but if you have any feature requests, suggestions, or concerns, please open an issue on the GitHub repository. Contributions are welcome.