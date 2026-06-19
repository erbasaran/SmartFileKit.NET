using System;
using System.IO;
using SmartFileKit.Domain;
using SmartFileKit.Detection;

namespace SmartFileKit.Security
{
    /// <summary>
    /// Represents a unified identity model for a file, combining physical and semantic signatures.
    /// </summary>
    public class FileFingerprint
    {
        /// <summary>
        /// Gets the size of the file in bytes.
        /// </summary>
        public long Size { get; }

        /// <summary>
        /// Gets the SHA256 checksum fingerprint.
        /// </summary>
        public string Sha256 { get; }

        /// <summary>
        /// Gets the detected or mapped MIME type.
        /// </summary>
        public string MimeType { get; }

        /// <summary>
        /// Gets the identified signature extension type (e.g. "pdf").
        /// </summary>
        public string SignatureType { get; }

        /// <summary>
        /// Gets the classification category of the file format.
        /// </summary>
        public FileCategory Category { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileFingerprint"/> class.
        /// </summary>
        public FileFingerprint(long size, string sha256, string mimeType, string signatureType, FileCategory category)
        {
            Size = size;
            Sha256 = sha256 ?? throw new ArgumentNullException(nameof(sha256));
            MimeType = mimeType ?? "application/octet-stream";
            SignatureType = signatureType ?? "unknown";
            Category = category;
        }

        /// <summary>
        /// Generates a unified file fingerprint from the specified stream.
        /// Does not close the stream and resets its position if seekable.
        /// </summary>
        public static FileFingerprint Generate(Stream stream, string fileName = null, string contentType = null)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            long size = 0;
            if (stream.CanSeek)
            {
                size = stream.Length;
            }

            // 1. Calculate hash (reads to end, then resets seekable stream)
            string sha256 = FileHash.Sha256(stream);

            // 2. Read header buffer (up to 4096 bytes)
            long originalPosition = 0;
            bool canSeek = stream.CanSeek;
            if (canSeek)
            {
                originalPosition = stream.Position;
            }

            byte[] buffer = new byte[4096];
            int totalBytesRead = 0;
            try
            {
                int bytesRead;
                while (totalBytesRead < buffer.Length &&
                       (bytesRead = stream.Read(buffer, totalBytesRead, buffer.Length - totalBytesRead)) > 0)
                {
                    totalBytesRead += bytesRead;
                }
            }
            catch
            {
                // Ignore read failure
            }
            finally
            {
                if (canSeek)
                {
                    try { stream.Position = originalPosition; } catch { }
                }
            }

            // Trim buffer
            byte[] activeBuffer = buffer;
            if (totalBytesRead < buffer.Length)
            {
                activeBuffer = new byte[totalBytesRead];
                Array.Copy(buffer, activeBuffer, totalBytesRead);
            }

            // 3. Detect format info
            FileFormatInfo format = null;
            if (activeBuffer.Length > 0)
            {
                format = FormatDetector.Detect(activeBuffer);
            }

            string fileExt = string.Empty;
            if (!string.IsNullOrEmpty(fileName))
            {
                try
                {
                    fileExt = Path.GetExtension(fileName).Trim().ToLowerInvariant();
                }
                catch
                {
                    // Ignore path errors
                }
            }

            string signatureType = format?.Extension?.TrimStart('.') ?? "unknown";
            string mimeType = format?.MimeType ?? MimeMapper.GetMimeType(fileExt);
            FileCategory category = format?.Category ?? MimeMapper.GetCategory(fileExt);

            if (!string.IsNullOrEmpty(contentType) && mimeType == "application/octet-stream")
            {
                mimeType = contentType;
            }

            return new FileFingerprint(size, sha256, mimeType, signatureType, category);
        }

        /// <summary>
        /// Determines whether this fingerprint matches another fingerprint (by size and SHA256 checksum).
        /// </summary>
        public bool Equals(FileFingerprint other)
        {
            if (other == null) return false;
            return Size == other.Size &&
                   string.Equals(Sha256, other.Sha256, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Serves as the default hash function.
        /// </summary>
        public override int GetHashCode()
        {
            return Size.GetHashCode() ^ Sha256.GetHashCode();
        }

        /// <summary>
        /// Returns a string representation of the fingerprint.
        /// </summary>
        public override string ToString() => $"[Fingerprint] Size: {Size} bytes, SHA256: {Sha256}, Mime: {MimeType}, Category: {Category}";
    }
}
