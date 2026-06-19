namespace SmartFileKit.Domain
{
    /// <summary>
    /// Represents standard, strongly-typed security findings during file analysis.
    /// </summary>
    public enum IssueType
    {
        /// <summary>
        /// A spoofing attack where the file header signature differs from the file extension's expected type.
        /// </summary>
        SignatureMismatch,

        /// <summary>
        /// A mismatch between the client-provided MIME content type and the extension or detected content format.
        /// </summary>
        MimeMismatch,

        /// <summary>
        /// The file extension is potentially dangerous or suspicious (e.g. executables or scripts).
        /// </summary>
        SuspiciousExtension,

        /// <summary>
        /// The file format cannot be recognized by its magic bytes signature.
        /// </summary>
        UnknownFileType,

        /// <summary>
        /// The file structure is malformed or throws parser errors, representing corruption.
        /// </summary>
        CorruptedFile,

        /// <summary>
        /// The uploaded file is completely empty (0 bytes).
        /// </summary>
        EmptyFile,

        /// <summary>
        /// The file has an invalid or missing signature header for the expected format.
        /// </summary>
        InvalidHeader,

        /// <summary>
        /// The file contains multiple distinct magic byte signatures (e.g., polyglot files).
        /// </summary>
        MultipleSignatureDetected,

        /// <summary>
        /// Potentially dangerous executable code/binary content has been detected (e.g., inside archives or raw).
        /// </summary>
        ExecutableContentDetected
    }
}
