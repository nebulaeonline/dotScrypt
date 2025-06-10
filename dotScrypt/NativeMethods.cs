using nebulae.dotScrypt;
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace nebulae.dotScrypt
{
    internal static class NativeMethods
    {
        private static bool _loaded;

        public static void Init()
        {
            if (_loaded)
                return;

            NativeLibrary.SetDllImportResolver(typeof(Scrypt).Assembly, ResolveNativeLibrary);
            _loaded = true;
        }

        private static IntPtr ResolveNativeLibrary(string libraryName, Assembly assembly, DllImportSearchPath? paths)
        {
            string fullPath = Path.Combine(AppContext.BaseDirectory, GetPlatformLibraryName());

            if (!File.Exists(fullPath))
                throw new DllNotFoundException($"Could not locate native libscrypt at path: {fullPath}");

            return NativeLibrary.Load(fullPath);
        }

        private static string GetPlatformLibraryName()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return Path.Combine("runtimes", "win-x64", "native", "libscrypt.dll");

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return Path.Combine("runtimes", "linux-x64", "native", "libscrypt.so");

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
                    return Path.Combine("runtimes", "osx-arm64", "native", "libscrypt.dylib");

                return Path.Combine("runtimes", "osx-x64", "native", "libscrypt.dylib");
            }

            throw new PlatformNotSupportedException("Unsupported OS platform");
        }

        [DllImport("libscrypt", CallingConvention = CallingConvention.Cdecl, EntryPoint = "scrypt_kdf")]
        internal static extern int scrypt_kdf(
            byte[] password, UIntPtr passwordLen,
            byte[] salt, UIntPtr saltLen,
            ulong N, uint r, uint p,
            byte[] output, UIntPtr outputLen);
    }
}
