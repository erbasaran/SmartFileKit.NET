namespace SmartFileKit.Security
{
    /// <summary>
    /// Represents the cryptographic hash algorithms supported by the hashing engine.
    /// </summary>
    public enum HashAlgorithmType
    {
        /// <summary>
        /// Message Digest 5 algorithm (128-bit hash).
        /// </summary>
        MD5,

        /// <summary>
        /// Secure Hash Algorithm 1 (160-bit hash).
        /// </summary>
        SHA1,

        /// <summary>
        /// Secure Hash Algorithm 2 with 256-bit hash.
        /// </summary>
        SHA256,

        /// <summary>
        /// Secure Hash Algorithm 2 with 512-bit hash.
        /// </summary>
        SHA512
    }
}
