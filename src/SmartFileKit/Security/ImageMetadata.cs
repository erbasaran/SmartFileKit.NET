using System;
using System.IO;

namespace SmartFileKit.Security
{
    /// <summary>
    /// Provides low-overhead, dependency-free image dimension and format readers.
    /// Supports JPEG, PNG, BMP, GIF, and WebP (lossy, lossless, and extended VP8X formats).
    /// </summary>
    public static class ImageMetadata
    {
        /// <summary>
        /// Reads image dimensions and format details from a stream without loading the file into memory.
        /// Does not close the stream and resets its position if seekable.
        /// </summary>
        public static ImageMetadataResult Read(Stream stream)
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
                // Read first 2 bytes to check magic signature
                int b1 = stream.ReadByte();
                int b2 = stream.ReadByte();
                if (b1 == -1 || b2 == -1) return ImageMetadataResult.Invalid();

                // Seek back to start of signature
                if (canSeek)
                {
                    stream.Position = originalPosition;
                }

                // If stream is not seekable, buffer the prefix chunk (up to 4096 bytes)
                Stream seekableStream = stream;
                MemoryStream bufferedStream = null;
                if (!canSeek)
                {
                    bufferedStream = new MemoryStream();
                    bufferedStream.WriteByte((byte)b1);
                    bufferedStream.WriteByte((byte)b2);
                    byte[] tempBuffer = new byte[4096];
                    int read = stream.Read(tempBuffer, 0, tempBuffer.Length);
                    if (read > 0)
                    {
                        bufferedStream.Write(tempBuffer, 0, read);
                    }
                    bufferedStream.Position = 0;
                    seekableStream = bufferedStream;
                }

                try
                {
                    // Check signatures
                    if (b1 == 0x89 && b2 == 0x50) // PNG
                        return ReadPng(seekableStream);
                    if (b1 == 0xFF && b2 == 0xD8) // JPEG
                        return ReadJpeg(seekableStream);
                    if (b1 == 'G' && b2 == 'I') // GIF
                        return ReadGif(seekableStream);
                    if (b1 == 0x42 && b2 == 0x4D) // BMP
                        return ReadBmp(seekableStream);
                    if (b1 == 'R' && b2 == 'I') // WebP (RIFF)
                        return ReadWebP(seekableStream);

                    return ImageMetadataResult.Invalid();
                }
                finally
                {
                    if (bufferedStream != null)
                    {
                        bufferedStream.Dispose();
                    }
                }
            }
            finally
            {
                if (canSeek)
                {
                    try { stream.Position = originalPosition; } catch { }
                }
            }
        }

        private static ImageMetadataResult ReadPng(Stream stream)
        {
            byte[] header = new byte[24];
            if (stream.Read(header, 0, 24) < 24)
                return ImageMetadataResult.Invalid();

            // Verify PNG Signature
            if (header[0] != 0x89 || header[1] != 0x50 || header[2] != 0x4E || header[3] != 0x47 ||
                header[4] != 0x0D || header[5] != 0x0A || header[6] != 0x1A || header[7] != 0x0A)
            {
                return ImageMetadataResult.Invalid();
            }

            // Verify 'IHDR' chunk starts at offset 12
            if (header[12] == 0x49 && header[13] == 0x48 && header[14] == 0x44 && header[15] == 0x52)
            {
                int width = (header[16] << 24) | (header[17] << 16) | (header[18] << 8) | header[19];
                int height = (header[20] << 24) | (header[21] << 16) | (header[22] << 8) | header[23];
                return new ImageMetadataResult(width, height, "PNG", true);
            }

            return ImageMetadataResult.Invalid();
        }

        private static ImageMetadataResult ReadJpeg(Stream stream)
        {
            // Skip SOI (FF D8)
            int b1 = stream.ReadByte();
            int b2 = stream.ReadByte();
            if (b1 != 0xFF || b2 != 0xD8)
                return ImageMetadataResult.Invalid();

            while (true)
            {
                int markerFF = stream.ReadByte();
                if (markerFF == -1) break;
                if (markerFF != 0xFF) continue; // Scan for marker prefix

                int markerType = stream.ReadByte();
                if (markerType == -1 || markerType == 0xD9 || markerType == 0xDA) // EOI or SOS
                    break;

                // Read length (2 bytes, Big Endian)
                int lenHigh = stream.ReadByte();
                int lenLow = stream.ReadByte();
                if (lenHigh == -1 || lenLow == -1) break;
                int len = (lenHigh << 8) | lenLow;

                // SOF markers (Start of Frame)
                // C0-CF except C4 (DHT), C8 (JPG extensions), CC (DAC)
                if (markerType >= 0xC0 && markerType <= 0xCF &&
                    markerType != 0xC4 && markerType != 0xC8 && markerType != 0xCC)
                {
                    int precision = stream.ReadByte();
                    int heightHigh = stream.ReadByte();
                    int heightLow = stream.ReadByte();
                    int widthHigh = stream.ReadByte();
                    int widthLow = stream.ReadByte();

                    if (widthHigh == -1 || widthLow == -1 || heightHigh == -1 || heightLow == -1)
                        break;

                    int height = (heightHigh << 8) | heightLow;
                    int width = (widthHigh << 8) | widthLow;
                    return new ImageMetadataResult(width, height, "JPEG", true);
                }
                else
                {
                    // Skip payload bytes (length includes length field, so subtract 2)
                    long skip = len - 2;
                    if (stream.CanSeek)
                    {
                        stream.Seek(skip, SeekOrigin.Current);
                    }
                    else
                    {
                        for (int i = 0; i < skip; i++)
                        {
                            if (stream.ReadByte() == -1) break;
                        }
                    }
                }
            }

            return ImageMetadataResult.Invalid();
        }

        private static ImageMetadataResult ReadGif(Stream stream)
        {
            byte[] header = new byte[10];
            if (stream.Read(header, 0, 10) < 10)
                return ImageMetadataResult.Invalid();

            // Verify GIF87a or GIF89a
            if (header[0] != 'G' || header[1] != 'I' || header[2] != 'F' ||
                header[3] != '8' || (header[4] != '7' && header[4] != '9') ||
                header[5] != 'a')
            {
                return ImageMetadataResult.Invalid();
            }

            int width = header[6] | (header[7] << 8);
            int height = header[8] | (header[9] << 8);
            return new ImageMetadataResult(width, height, "GIF", true);
        }

        private static ImageMetadataResult ReadBmp(Stream stream)
        {
            byte[] header = new byte[26];
            if (stream.Read(header, 0, 26) < 26)
                return ImageMetadataResult.Invalid();

            // BM magic check
            if (header[0] != 0x42 || header[1] != 0x4D)
                return ImageMetadataResult.Invalid();

            int width = header[18] | (header[19] << 8) | (header[20] << 16) | (header[21] << 24);
            int height = header[22] | (header[23] << 8) | (header[24] << 16) | (header[25] << 24);

            return new ImageMetadataResult(width, Math.Abs(height), "BMP", true);
        }

        private static ImageMetadataResult ReadWebP(Stream stream)
        {
            byte[] header = new byte[30];
            if (stream.Read(header, 0, 30) < 30)
                return ImageMetadataResult.Invalid();

            // Check RIFF and WEBP
            if (header[0] != 'R' || header[1] != 'I' || header[2] != 'F' || header[3] != 'F' ||
                header[8] != 'W' || header[9] != 'E' || header[10] != 'B' || header[11] != 'P')
            {
                return ImageMetadataResult.Invalid();
            }

            string subFormat = System.Text.Encoding.ASCII.GetString(header, 12, 4);

            if (subFormat == "VP8 ")
            {
                // Sync code keyframe sync check: 9D 01 2A at offset 23
                if (header[23] == 0x9D && header[24] == 0x01 && header[25] == 0x2A)
                {
                    int width = (header[26] | (header[27] << 8)) & 0x3FFF;
                    int height = (header[28] | (header[29] << 8)) & 0x3FFF;
                    return new ImageMetadataResult(width, height, "WebP", true);
                }
            }
            else if (subFormat == "VP8L")
            {
                // Lossless VP8L signature check: 0x2F at offset 20
                if (header[20] == 0x2F)
                {
                    int val = header[21] | (header[22] << 8) | (header[23] << 16) | (header[24] << 24);
                    int width = 1 + (val & 0x3FFF);
                    int height = 1 + ((val >> 14) & 0x3FFF);
                    return new ImageMetadataResult(width, height, "WebP", true);
                }
            }
            else if (subFormat == "VP8X")
            {
                // Extended WebP dimensions (3 bytes each) starting at offset 24
                int width = 1 + (header[24] | (header[25] << 8) | (header[26] << 16));
                int height = 1 + (header[27] | (header[28] << 8) | (header[29] << 16));
                return new ImageMetadataResult(width, height, "WebP", true);
            }

            return new ImageMetadataResult(0, 0, "WebP", false);
        }
    }
}
