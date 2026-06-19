using System;

namespace SmartFileKit.Domain
{
    /// <summary>
    /// Represents a specific security finding or warning detected during file analysis.
    /// </summary>
    public class FileIssue
    {
        /// <summary>
        /// Gets the type of issue.
        /// </summary>
        public IssueType Type { get; }

        /// <summary>
        /// Gets a descriptive message explaining the finding.
        /// </summary>
        public string Description { get; }

        /// <summary>
        /// Gets the severity/risk level of this specific issue.
        /// </summary>
        public FileRiskLevel Severity { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileIssue"/> class.
        /// </summary>
        public FileIssue(IssueType type, string description, FileRiskLevel severity)
        {
            Type = type;
            Description = description ?? throw new ArgumentNullException(nameof(description));
            Severity = severity;
        }

        /// <summary>
        /// Returns a string representation of the file issue.
        /// </summary>
        public override string ToString() => $"[{Severity}] {Type}: {Description}";
    }
}
