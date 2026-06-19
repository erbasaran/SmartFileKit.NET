using System;
using System.IO;
using System.Text;

namespace SmartFileKit
{
    /// <summary>
    /// Provides filename sanitization and safety utilities.
    /// </summary>
    public static class FileName
    {
        private static readonly string[] WindowsReservedNames = new[]
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

        private static readonly char[] InvalidFileNameChars = Path.GetInvalidFileNameChars();

        /// <summary>
        /// Sanitizes a filename, protecting against path traversal, Turkish character issues,
        /// and cross-platform incompatibilities (such as Windows reserved names).
        /// </summary>
        /// <param name="fileName">The filename to sanitize.</param>
        /// <param name="replacement">The character to replace invalid characters with.</param>
        /// <returns>A safe, sanitized filename.</returns>
        public static string Sanitize(string fileName, char replacement = '_')
        {
            if (string.IsNullOrWhiteSpace(fileName))
            {
                return "file";
            }

            // 1. Normalize Turkish characters (e.g., 'ü' -> 'u', 'Ş' -> 'S')
            string sanitized = NormalizeTurkishCharacters(fileName);

            // 2. Ensure the replacement character itself is valid
            if (Array.IndexOf(InvalidFileNameChars, replacement) >= 0 || replacement == '/' || replacement == '\\')
            {
                replacement = '_';
            }

            // 3. Path Traversal Protection: Remove relative segments (e.g. "..")
            sanitized = sanitized.Replace("..", "");

            // Trim leading/trailing separators, dots, and spaces to clear out relative roots
            char[] trimChars = new[] { '/', '\\', '.', ' ' };
            sanitized = sanitized.Trim(trimChars);

            // 4. Remove/Replace invalid file name chars and directory separators
            var sb = new StringBuilder(sanitized.Length);
            foreach (char c in sanitized)
            {
                if (Array.IndexOf(InvalidFileNameChars, c) >= 0 || c == '/' || c == '\\')
                {
                    // Append replacement instead of invalid char
                    sb.Append(replacement);
                }
                else
                {
                    sb.Append(c);
                }
            }
            sanitized = sb.ToString();

            // 5. Extract name and extension for length and reserved word checks
            string namePart = Path.GetFileNameWithoutExtension(sanitized);
            string extPart = Path.GetExtension(sanitized);

            // If name part is empty or contains only replacement characters, default it
            if (string.IsNullOrWhiteSpace(namePart) || namePart.Trim(replacement).Length == 0)
            {
                namePart = "file";
            }

            // 6. Windows Reserved Device Name handling (e.g. CON.txt -> _CON.txt)
            string upperName = namePart.Trim().ToUpperInvariant();
            foreach (string reserved in WindowsReservedNames)
            {
                if (upperName == reserved)
                {
                    namePart = "_" + namePart;
                    break;
                }
            }

            // 7. Max length limit check (truncating name part to fit 255 chars including extension)
            const int maxFileNameLength = 255;
            int totalLength = namePart.Length + extPart.Length;
            if (totalLength > maxFileNameLength)
            {
                int allowedNameLength = maxFileNameLength - extPart.Length;
                if (allowedNameLength <= 0)
                {
                    // Extension itself is too long, truncate it
                    string combined = namePart + extPart;
                    sanitized = combined.Substring(0, maxFileNameLength);
                }
                else
                {
                    namePart = namePart.Substring(0, allowedNameLength);
                    sanitized = namePart + extPart;
                }
            }
            else
            {
                sanitized = namePart + extPart;
            }

            // Double check empty outcome
            if (string.IsNullOrWhiteSpace(sanitized) || sanitized.Trim(replacement).Length == 0)
            {
                return "file";
            }

            return sanitized;
        }

        /// <summary>
        /// Normalizes Turkish characters to their English equivalents.
        /// </summary>
        private static string NormalizeTurkishCharacters(string text)
        {
            if (string.IsNullOrEmpty(text))
                return text;

            char[] chars = text.ToCharArray();
            bool changed = false;

            for (int i = 0; i < chars.Length; i++)
            {
                char c = chars[i];
                char normalized = c;

                switch (c)
                {
                    case 'ı': normalized = 'i'; changed = true; break;
                    case 'İ': normalized = 'I'; changed = true; break;
                    case 'ğ': normalized = 'g'; changed = true; break;
                    case 'Ğ': normalized = 'G'; changed = true; break;
                    case 'ü': normalized = 'u'; changed = true; break;
                    case 'Ü': normalized = 'U'; changed = true; break;
                    case 'ş': normalized = 's'; changed = true; break;
                    case 'Ş': normalized = 'S'; changed = true; break;
                    case 'ö': normalized = 'o'; changed = true; break;
                    case 'Ö': normalized = 'O'; changed = true; break;
                    case 'ç': normalized = 'c'; changed = true; break;
                    case 'Ç': normalized = 'C'; changed = true; break;
                }

                chars[i] = normalized;
            }

            return changed ? new string(chars) : text;
        }
    }
}
