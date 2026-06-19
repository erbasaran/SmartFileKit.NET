namespace SmartFileKit.Domain
{
    /// <summary>
    /// Configures the behavior of the file analysis process.
    /// </summary>
    public class FileAnalysisOptions
    {
        /// <summary>
        /// Gets or sets whether magic bytes/signature validation is performed. Defaults to true.
        /// </summary>
        public bool ValidateSignature { get; set; } = true;

        /// <summary>
        /// Gets or sets whether client MIME and extension matching validation is performed. Defaults to true.
        /// </summary>
        public bool ValidateMime { get; set; } = true;

        /// <summary>
        /// Gets or sets whether structural checks (e.g. verifying ZIP integrity or Office contents) are performed. Defaults to true.
        /// </summary>
        public bool ValidateStructure { get; set; } = true;

        /// <summary>
        /// Gets or sets whether a security risk score between 0 and 100 is calculated. Defaults to true.
        /// </summary>
        public bool CalculateRiskScore { get; set; } = true;

        /// <summary>
        /// Gets or sets whether file Shannon Entropy is computed to find obfuscated payloads. Defaults to false.
        /// </summary>
        public bool CheckEntropy { get; set; } = false;

        /// <summary>
        /// Gets or sets the threshold above which file entropy is flagged as suspicious for non-compressed types. Defaults to 7.5.
        /// </summary>
        public double EntropyThreshold { get; set; } = 7.5;

        /// <summary>
        /// Gets or sets the maximum bytes to read for entropy calculations. Defaults to 1 MB (1024 * 1024 bytes).
        /// </summary>
        public int MaxBytesForEntropy { get; set; } = 1024 * 1024;
    }
}
