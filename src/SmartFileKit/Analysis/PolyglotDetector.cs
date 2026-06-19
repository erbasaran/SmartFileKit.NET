using System;
using SmartFileKit.Domain;

namespace SmartFileKit.Analysis
{
    /// <summary>
    /// Detects polyglot files containing multiple distinct headers (e.g., PDF + Executable, ZIP + Executable).
    /// </summary>
    public static class PolyglotDetector
    {
        private static readonly byte[] ZipHeader = { 0x50, 0x4B, 0x03, 0x04 }; // PK..
        private static readonly byte[] PdfHeader = { 0x25, 0x50, 0x44, 0x46 }; // %PDF

        /// <summary>
        /// Scans the given buffer to determine if secondary format headers are present at non-standard offsets.
        /// </summary>
        /// <param name="buffer">The active byte buffer containing file prefix bytes.</param>
        /// <param name="detectedFormat">The primary file format detected by magic bytes.</param>
        /// <returns>True if a secondary signature is found at a non-standard offset; otherwise, false.</returns>
        public static bool Detect(byte[] buffer, FileFormatInfo detectedFormat)
        {
            if (buffer == null || buffer.Length < 4) return false;

            string primaryExtension = detectedFormat?.Extension ?? string.Empty;

            // 1. Scan for secondary ZIP signature (PK\x03\x04) at non-zero offsets
            if (primaryExtension != ".zip" && primaryExtension != ".docx" && primaryExtension != ".xlsx" && primaryExtension != ".pptx")
            {
                int zipOffset = IndexOf(buffer, ZipHeader, 1);
                if (zipOffset > 0)
                {
                    return true;
                }
            }

            // 2. Scan for secondary PDF signature (%PDF) at non-zero offsets
            if (primaryExtension != ".pdf")
            {
                int pdfOffset = IndexOf(buffer, PdfHeader, 1);
                if (pdfOffset > 0)
                {
                    return true;
                }
            }

            // 3. Scan for executable MZ at non-zero offset with structural PE check
            if (primaryExtension != ".exe" && primaryExtension != ".dll" && primaryExtension != ".sys")
            {
                int currentOffset = 1;
                while (currentOffset < buffer.Length - 64)
                {
                    int mzOffset = IndexOf(buffer, new byte[] { 0x4D, 0x5A }, currentOffset); // MZ
                    if (mzOffset < 0) break;

                    if (HasValidPeHeader(buffer, mzOffset))
                    {
                        return true;
                    }
                    currentOffset = mzOffset + 2;
                }
            }

            return false;
        }

        private static int IndexOf(byte[] array, byte[] pattern, int startOffset)
        {
            if (array == null || pattern == null || array.Length < pattern.Length + startOffset)
                return -1;

            int limit = array.Length - pattern.Length;
            for (int i = startOffset; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (array[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        private static bool HasValidPeHeader(byte[] buffer, int mzOffset)
        {
            if (mzOffset + 64 > buffer.Length) return false;

            // PE offset is stored at offset 0x3C (60) relative to MZ start
            int peOffsetValue = buffer[mzOffset + 0x3C] |
                                (buffer[mzOffset + 0x3D] << 8) |
                                (buffer[mzOffset + 0x3E] << 16) |
                                (buffer[mzOffset + 0x3F] << 24);

            if (peOffsetValue < 0 || mzOffset + peOffsetValue + 4 > buffer.Length) return false;

            // Check if PE\x00\x00 (0x50, 0x45, 0x00, 0x00) signature is present at the target offset
            return buffer[mzOffset + peOffsetValue] == 0x50 &&
                   buffer[mzOffset + peOffsetValue + 1] == 0x45 &&
                   buffer[mzOffset + peOffsetValue + 2] == 0x00 &&
                   buffer[mzOffset + peOffsetValue + 3] == 0x00;
        }
    }
}
