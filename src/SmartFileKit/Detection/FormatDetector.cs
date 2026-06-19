using SmartFileKit.Domain;
using System;
using System.IO;

namespace SmartFileKit.Detection
{
    /// <summary>
    /// Core engine for detecting file formats from streams, byte arrays, or file paths.
    /// </summary>
    public static class FormatDetector
    {
        private const int MaxDetectionBufferSize = 4096;

        /// <summary>
        /// Detects the file format info from the given stream.
        /// Does not close the stream and resets its position if it is seekable.
        /// </summary>
        public static FileFormatInfo Detect(Stream stream)
        {
            if (stream == null) return null;

            long originalPosition = 0;
            bool canSeek = stream.CanSeek;
            if (canSeek)
            {
                originalPosition = stream.Position;
            }

            byte[] buffer = new byte[MaxDetectionBufferSize];
            int totalBytesRead = 0;

            try
            {
                int bytesRead;
                while (totalBytesRead < buffer.Length &&
                       (bytesRead = stream.Read(buffer, totalBytesRead, buffer.Length - totalBytesRead)) > 0)
                {
                    totalBytesRead += bytesRead;
                }
            }
            catch
            {
                // Return null if reading failed (e.g. stream closed prematurely)
                return null;
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
                        // Ignore seek errors on reset
                    }
                }
            }

            if (totalBytesRead == 0)
                return null;

            // Trim buffer to actual read size
            byte[] activeBuffer = buffer;
            if (totalBytesRead < buffer.Length)
            {
                activeBuffer = new byte[totalBytesRead];
                Array.Copy(buffer, activeBuffer, totalBytesRead);
            }

            return Detect(activeBuffer);
        }

        /// <summary>
        /// Detects the file format info from a byte array.
        /// </summary>
        public static FileFormatInfo Detect(byte[] buffer)
        {
            if (buffer == null || buffer.Length == 0)
                return null;

            foreach (var format in FileFormatRegistry.Formats)
            {
                if (format.Matches(buffer))
                {
                    return format;
                }
            }

            return null;
        }

        /// <summary>
        /// Detects the file format info of a file at the specified path.
        /// </summary>
        public static FileFormatInfo Detect(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                return null;

            try
            {
                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    return Detect(fs);
                }
            }
            catch
            {
                return null;
            }
        }
    }
}
