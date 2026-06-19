using System;
using System.Collections.Generic;

namespace SmartFileKit.Domain
{
    /// <summary>
    /// Represents the comprehensive report generated after analyzing a file.
    /// </summary>
    public class FileAnalysisReport
    {
        /// <summary>
        /// Gets the actual file type extension determined by signature or inspection (e.g., "pdf", "exe", "docx").
        /// </summary>
        public string ActualFileType { get; }

        /// <summary>
        /// Gets the actual detected MIME type of the file.
        /// </summary>
        public string DetectedMimeType { get; }

        /// <summary>
        /// Gets a value indicating whether the file is determined to be safe (Risk score 0-20 and no major issues).
        /// </summary>
        public bool IsSafe { get; }

        /// <summary>
        /// Gets a value indicating whether the file is suspicious (Risk score > 20 or any warnings found).
        /// </summary>
        public bool IsSuspicious { get; }

        /// <summary>
        /// Gets the security risk score, ranging from 0 (completely safe) to 100 (highest risk).
        /// </summary>
        public int RiskScore { get; }

        /// <summary>
        /// Gets the overall risk level category.
        /// </summary>
        public FileRiskLevel RiskLevel { get; }

        /// <summary>
        /// Gets the list of security findings or warnings identified.
        /// </summary>
        public IReadOnlyList<FileIssue> Issues { get; }

        /// <summary>
        /// Gets the calculated Shannon Entropy of the file content, if checked.
        /// </summary>
        public double? Entropy { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileAnalysisReport"/> class.
        /// </summary>
        public FileAnalysisReport(
            string actualFileType,
            string detectedMimeType,
            int riskScore,
            FileRiskLevel riskLevel,
            IReadOnlyList<FileIssue> issues,
            double? entropy = null)
        {
            ActualFileType = actualFileType ?? string.Empty;
            DetectedMimeType = detectedMimeType ?? "application/octet-stream";
            RiskScore = Math.Max(0, Math.Min(100, riskScore));
            RiskLevel = riskLevel;
            Issues = issues ?? Array.Empty<FileIssue>();
            Entropy = entropy;

            // IsSafe: risk score <= 20 and no issues
            IsSafe = RiskScore <= 20 && Issues.Count == 0;

            // IsSuspicious: risk score > 20 or any issues
            IsSuspicious = RiskScore > 20 || Issues.Count > 0;
        }
    }
}
