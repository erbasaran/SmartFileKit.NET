using System;
using System.IO;

namespace SmartFileKit.Analysis
{
    /// <summary>
    /// Computes the Shannon Entropy of file streams or buffers to detect encrypted or obfuscated binary payloads.
    /// </summary>
    public static class EntropyCalculator
    {
        /// <summary>
        /// Calculates the Shannon Entropy of a byte buffer.
        /// </summary>
        /// <param name="buffer">The buffer containing file bytes.</param>
        /// <param name="length">The number of bytes to analyze.</param>
        /// <returns>A value between 0.0 (completely redundant) and 8.0 (completely random/obfuscated/compressed).</returns>
        public static double Calculate(byte[] buffer, int length)
        {
            if (buffer == null || length <= 0) return 0.0;

            int actualLength = Math.Min(buffer.Length, length);
            if (actualLength == 0) return 0.0;

            int[] counts = new int[256];
            for (int i = 0; i < actualLength; i++)
            {
                counts[buffer[i]]++;
            }

            double entropy = 0.0;
            double log2 = Math.Log(2);

            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double probability = (double)counts[i] / actualLength;
                    entropy -= probability * (Math.Log(probability) / log2);
                }
            }

            return entropy;
        }

        /// <summary>
        /// Calculates the Shannon Entropy of a stream by reading up to a specified maximum number of bytes in chunks.
        /// Does not close the stream and resets its position if seekable.
        /// </summary>
        public static double Calculate(Stream stream, out long totalBytesRead, int maxBytesToRead = 1024 * 1024)
        {
            totalBytesRead = 0;
            if (stream == null) return 0.0;

            long originalPosition = 0;
            bool canSeek = stream.CanSeek;
            if (canSeek)
            {
                originalPosition = stream.Position;
            }

            int[] counts = new int[256];
            byte[] chunkBuffer = new byte[4096];
            int bytesRead;

            try
            {
                while (totalBytesRead < maxBytesToRead)
                {
                    int bytesToRead = (int)Math.Min(chunkBuffer.Length, maxBytesToRead - totalBytesRead);
                    bytesRead = stream.Read(chunkBuffer, 0, bytesToRead);
                    if (bytesRead <= 0) break;

                    for (int i = 0; i < bytesRead; i++)
                    {
                        counts[chunkBuffer[i]]++;
                    }

                    totalBytesRead += bytesRead;
                }
            }
            catch
            {
                // In case of read failure, compute entropy on whatever was read so far.
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

            if (totalBytesRead == 0) return 0.0;

            double entropy = 0.0;
            double log2 = Math.Log(2);

            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double probability = (double)counts[i] / totalBytesRead;
                    entropy -= probability * (Math.Log(probability) / log2);
                }
            }

            return entropy;
        }
    }
}
