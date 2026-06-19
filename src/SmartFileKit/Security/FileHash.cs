using System;
using System.IO;
using System.Security.Cryptography;

namespace SmartFileKit.Security
{
    /// <summary>
    /// Provides cryptographic hashing utility functions for streams and bytes, optimized for low-allocation.
    /// </summary>
    public static class FileHash
    {
        /// <summary>
        /// Calculates the SHA256 hash of a file stream.
        /// Does not close the stream and resets its position if seekable.
        /// </summary>
        public static string Sha256(Stream stream) => Calculate(stream, HashAlgorithmType.SHA256);

        /// <summary>
        /// Calculates the specified cryptographic hash of a file stream.
        /// Does not close the stream and resets its position if seekable.
        /// </summary>
        public static string Calculate(Stream stream, HashAlgorithmType algorithm)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            long originalPosition = 0;
            bool canSeek = stream.CanSeek;
            if (canSeek)
            {
                originalPosition = stream.Position;
            }

            try
            {
                using (var hashAlgo = CreateHashAlgorithm(algorithm))
                {
                    byte[] hashBytes = hashAlgo.ComputeHash(stream);
                    return ToHex(hashBytes);
                }
            }
            finally
            {
                if (canSeek)
                {
                    try
                    {
                        stream.Position = originalPosition;
                    }
                    catch
                    {
                        // Ignore position reset failure
                    }
                }
            }
        }

        private static HashAlgorithm CreateHashAlgorithm(HashAlgorithmType algorithm)
        {
            switch (algorithm)
            {
                case HashAlgorithmType.MD5:
                    return MD5.Create();
                case HashAlgorithmType.SHA1:
                    return SHA1.Create();
                case HashAlgorithmType.SHA256:
                    return SHA256.Create();
                case HashAlgorithmType.SHA512:
                    return SHA512.Create();
                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm), $"Unsupported hash algorithm: {algorithm}");
            }
        }

        private static string ToHex(byte[] bytes)
        {
            char[] c = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];
                c[i * 2] = GetHexChar(b >> 4);
                c[i * 2 + 1] = GetHexChar(b & 0x0F);
            }
            return new string(c);
        }

        private static char GetHexChar(int val)
        {
            return val < 10 ? (char)('0' + val) : (char)('a' + (val - 10));
        }
    }
}
