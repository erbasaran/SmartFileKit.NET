using SmartFileKit.Detection;
using System;
using System.Collections.Generic;

namespace SmartFileKit.Domain
{
    /// <summary>
    /// Holds the metadata, mime mapping, category, and detection signatures for a specific file format.
    /// </summary>
    public class FileFormatInfo
    {
        /// <summary>
        /// Gets the primary file extension (e.g. ".jpg"). Always starts with a dot and is lowercase.
        /// </summary>
        public string Extension { get; }

        /// <summary>
        /// Gets the MIME type associated with the format (e.g. "image/jpeg").
        /// </summary>
        public string MimeType { get; }

        /// <summary>
        /// Gets the classification category of this format (e.g. Image, Archive).
        /// </summary>
        public FileCategory Category { get; }

        /// <summary>
        /// Gets the list of signatures (magic bytes) that can identify this file type.
        /// </summary>
        public IReadOnlyList<FileSignature> Signatures { get; }

        /// <summary>
        /// Gets the optional validator for text-based or complex structural content verification.
        /// </summary>
        public Func<byte[], bool> ExtraValidator { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileFormatInfo"/> class.
        /// </summary>
        public FileFormatInfo(
            string extension,
            string mimeType,
            FileCategory category,
            IReadOnlyList<FileSignature> signatures = null,
            Func<byte[], bool> extraValidator = null)
        {
            if (string.IsNullOrEmpty(extension))
                throw new ArgumentException("Extension cannot be null or empty.", nameof(extension));
            if (string.IsNullOrEmpty(mimeType))
                throw new ArgumentException("MimeType cannot be null or empty.", nameof(mimeType));

            Extension = extension.StartsWith(".") ? extension.ToLowerInvariant() : "." + extension.ToLowerInvariant();
            MimeType = mimeType.ToLowerInvariant();
            Category = category;
            Signatures = signatures ?? Array.Empty<FileSignature>();
            ExtraValidator = extraValidator;
        }

        /// <summary>
        /// Checks if a buffer matches any of the registered signatures or custom content validators.
        /// </summary>
        public bool Matches(byte[] buffer)
        {
            if (buffer == null || buffer.Length == 0)
                return false;

            // If we have signatures, at least one must match
            if (Signatures.Count > 0)
            {
                bool signatureMatched = false;
                foreach (var signature in Signatures)
                {
                    if (signature.Matches(buffer))
                    {
                        signatureMatched = true;
                        break;
                    }
                }

                if (!signatureMatched)
                    return false;
            }

            // If we also have a custom validator, run it
            if (ExtraValidator != null)
            {
                return ExtraValidator(buffer);
            }

            return Signatures.Count > 0; // If no extra validator and matched signature, return true. Otherwise false.
        }
    }
}
