namespace SmartFileKit.Domain
{
    /// <summary>
    /// Represents the security risk levels assigned to analyzed files.
    /// </summary>
    public enum FileRiskLevel
    {
        /// <summary>
        /// The file is determined to be safe (Risk score 0-20).
        /// </summary>
        Safe,

        /// <summary>
        /// The file presents low security risks (Risk score 21-50).
        /// </summary>
        Low,

        /// <summary>
        /// The file presents medium security risks (Risk score 51-80).
        /// </summary>
        Medium,

        /// <summary>
        /// The file presents high security risks (Risk score 81-100).
        /// </summary>
        High
    }
}
