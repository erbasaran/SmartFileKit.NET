using System;
using System.IO;

namespace SmartFileKit.Security
{
    /// <summary>
    /// Provides utilities for comparing files and identifying duplicates based on streams, hashes, or fingerprints.
    /// </summary>
    public static class DuplicateDetector
    {
        /// <summary>
        /// Compares two cryptographic hash strings for equality.
        /// </summary>
        public static bool Compare(string hash1, string hash2)
        {
            if (hash1 == null || hash2 == null) return false;
            return hash1.Equals(hash2, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Compares two file fingerprints for equality.
        /// </summary>
        public static bool AreSame(FileFingerprint fingerprint1, FileFingerprint fingerprint2)
        {
            if (fingerprint1 == null || fingerprint2 == null) return false;
            return fingerprint1.Equals(fingerprint2);
        }

        /// <summary>
        /// Compares two streams byte-by-byte to determine if they are identical.
        /// Does not close the streams and resets their position if seekable.
        /// </summary>
        public static bool AreSame(Stream stream1, Stream stream2)
        {
            if (stream1 == null || stream2 == null) return false;

            // Fast size check if both streams support seeking
            if (stream1.CanSeek && stream2.CanSeek)
            {
                if (stream1.Length != stream2.Length) return false;
            }

            long originalPos1 = stream1.CanSeek ? stream1.Position : 0;
            long originalPos2 = stream2.CanSeek ? stream2.Position : 0;

            try
            {
                byte[] buffer1 = new byte[4096];
                byte[] buffer2 = new byte[4096];

                while (true)
                {
                    int bytesRead1 = stream1.Read(buffer1, 0, buffer1.Length);
                    int bytesRead2 = stream2.Read(buffer2, 0, buffer2.Length);

                    if (bytesRead1 != bytesRead2) return false;
                    if (bytesRead1 == 0) return true;

                    // Compare arrays byte-by-byte
                    for (int i = 0; i < bytesRead1; i++)
                    {
                        if (buffer1[i] != buffer2[i]) return false;
                    }
                }
            }
            finally
            {
                if (stream1.CanSeek)
                {
                    try { stream1.Position = originalPos1; } catch { }
                }
                if (stream2.CanSeek)
                {
                    try { stream2.Position = originalPos2; } catch { }
                }
            }
        }
    }
}
