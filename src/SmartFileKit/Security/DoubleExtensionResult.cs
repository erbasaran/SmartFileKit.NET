namespace SmartFileKit.Security
{
    /// <summary>
    /// Represents the result of analyzing a filename for double extensions.
    /// </summary>
    public class DoubleExtensionResult
    {
        /// <summary>
        /// Gets a value indicating whether a double extension was detected (e.g. invoice.pdf.exe).
        /// </summary>
        public bool HasDoubleExtension { get; }

        /// <summary>
        /// Gets the primary extension (e.g. ".pdf").
        /// </summary>
        public string PrimaryExtension { get; }

        /// <summary>
        /// Gets the secondary/disguised extension (e.g. ".exe").
        /// </summary>
        public string SecondExtension { get; }

        /// <summary>
        /// Gets a value indicating whether the second extension is marked as dangerous.
        /// </summary>
        public bool IsDangerous { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="DoubleExtensionResult"/> class.
        /// </summary>
        public DoubleExtensionResult(bool hasDoubleExtension, string primaryExtension, string secondExtension, bool isDangerous)
        {
            HasDoubleExtension = hasDoubleExtension;
            PrimaryExtension = primaryExtension ?? string.Empty;
            SecondExtension = secondExtension ?? string.Empty;
            IsDangerous = isDangerous;
        }
    }
}
