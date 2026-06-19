using System.Collections.Generic;

namespace SmartFileKit.Security
{
    /// <summary>
    /// Represents the comprehensive results of a filename security risk analysis.
    /// </summary>
    public class FileNameAnalysisResult
    {
        /// <summary>
        /// Gets a value indicating whether the filename is clean and safe.
        /// </summary>
        public bool IsSafe { get; }

        /// <summary>
        /// Gets a value indicating whether a path traversal pattern was detected.
        /// </summary>
        public bool HasPathTraversal { get; }

        /// <summary>
        /// Gets a value indicating whether a Windows reserved device name was detected.
        /// </summary>
        public bool IsReservedName { get; }

        /// <summary>
        /// Gets a value indicating whether the name contains suspicious command or shell characters.
        /// </summary>
        public bool HasSuspiciousCharacters { get; }

        /// <summary>
        /// Gets the calculated threat risk score (0 to 100).
        /// </summary>
        public int RiskScore { get; }

        /// <summary>
        /// Gets the list of specific findings or warnings.
        /// </summary>
        public IReadOnlyList<string> Issues { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileNameAnalysisResult"/> class.
        /// </summary>
        public FileNameAnalysisResult(
            bool hasPathTraversal,
            bool isReservedName,
            bool hasSuspiciousCharacters,
            int riskScore,
            IReadOnlyList<string> issues)
        {
            HasPathTraversal = hasPathTraversal;
            IsReservedName = isReservedName;
            HasSuspiciousCharacters = hasSuspiciousCharacters;
            RiskScore = riskScore;
            Issues = issues ?? new List<string>().AsReadOnly();
            IsSafe = riskScore == 0;
        }
    }
}
