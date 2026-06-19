using System;
using System.Collections.Generic;
using System.IO;

namespace SmartFileKit.Security
{
    /// <summary>
    /// Provides filename-based and extension-based security threat checkers.
    /// </summary>
    public static class FileSecurity
    {
        private static readonly HashSet<string> DangerousExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".js",
            ".lnk", ".hta", ".pif", ".cpl", ".wsf", ".vbe", ".jse", ".reg", ".scr", ".msi"
        };

        private static readonly HashSet<string> ReservedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

        /// <summary>
        /// Determines whether the given filename ends with a high-risk dangerous extension.
        /// </summary>
        public static bool IsDangerousExtension(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return false;
            try
            {
                string ext = Path.GetExtension(fileName).Trim().ToLowerInvariant();
                return DangerousExtensions.Contains(ext);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Analyzes a filename to detect if it uses a disguised double extension (e.g. invoice.pdf.exe).
        /// </summary>
        public static DoubleExtensionResult HasDoubleExtension(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
                return new DoubleExtensionResult(false, null, null, false);

            string name = Path.GetFileName(fileName);
            string[] parts = name.Split('.');

            // To prevent false positives, we must ensure there are at least two extensions,
            // and the primary/second extensions are valid (e.g. not version numbers like v1.0.txt)
            if (parts.Length > 2)
            {
                string secondExt = "." + parts[parts.Length - 1].ToLowerInvariant();
                string primaryExt = "." + parts[parts.Length - 2].ToLowerInvariant();

                if (IsValidExtensionFormat(primaryExt) && IsValidExtensionFormat(secondExt))
                {
                    bool isDangerous = DangerousExtensions.Contains(secondExt);
                    return new DoubleExtensionResult(true, primaryExt, secondExt, isDangerous);
                }
            }

            return new DoubleExtensionResult(false, null, null, false);
        }

        /// <summary>
        /// Conducts a comprehensive threat analysis on a filename, flagging path traversal, Win32 reserved names, and shell chars.
        /// </summary>
        public static FileNameAnalysisResult AnalyzeFileName(string fileName)
        {
            var issues = new List<string>();
            bool hasPathTraversal = false;
            bool isReservedName = false;
            bool hasSuspiciousCharacters = false;
            int riskScore = 0;

            if (string.IsNullOrEmpty(fileName))
            {
                issues.Add("Filename is empty.");
                return new FileNameAnalysisResult(false, false, false, 10, issues.AsReadOnly());
            }

            // 1. Path traversal checks (raw and URL-decoded)
            string normalized = fileName.Replace('\\', '/');
            string decoded = normalized;
            try
            {
                decoded = System.Net.WebUtility.UrlDecode(normalized);
            }
            catch
            {
                // Ignore decoding errors
            }

            if (normalized.Contains("../") || normalized.Contains("..") ||
                decoded.Contains("../") || decoded.Contains(".."))
            {
                hasPathTraversal = true;
                issues.Add("Path traversal pattern (..) detected.");
                riskScore += 80;
            }

            // 2. Windows reserved device names
            string filenameWithoutExt = Path.GetFileNameWithoutExtension(fileName);
            if (ReservedNames.Contains(filenameWithoutExt))
            {
                isReservedName = true;
                issues.Add($"Windows reserved device name '{filenameWithoutExt}' detected.");
                riskScore += 50;
            }

            // 3. Suspicious command execution and shell characters
            char[] suspiciousChars = { ';', '|', '&', '$', '>', '<', '`', '\'', '"', '\0', '\n', '\r' };
            foreach (char c in suspiciousChars)
            {
                if (fileName.IndexOf(c) >= 0)
                {
                    hasSuspiciousCharacters = true;
                    issues.Add($"Suspicious command character '{c}' detected.");
                    riskScore += 30;
                }
            }

            riskScore = Math.Min(100, riskScore);

            return new FileNameAnalysisResult(hasPathTraversal, isReservedName, hasSuspiciousCharacters, riskScore, issues.AsReadOnly());
        }

        private static bool IsValidExtensionFormat(string ext)
        {
            if (string.IsNullOrEmpty(ext) || ext.Length < 2) return false;
            
            // Starts with dot
            if (ext[0] != '.') return false;

            // Rest should be alphanumeric (preventing false positives like version dots .0 or .12)
            bool hasLetter = false;
            for (int i = 1; i < ext.Length; i++)
            {
                char c = ext[i];
                if (!char.IsLetterOrDigit(c)) return false;
                if (char.IsLetter(c)) hasLetter = true;
            }

            return hasLetter; // An extension must contain at least one letter (e.g. .7z, .jpg)
        }
    }
}
