using System;
using System.Collections.Generic;

namespace SmartFileKit.Analysis.Archives
{
    /// <summary>
    /// Represents findings from an archive inspection process.
    /// </summary>
    public class ArchiveInspectionResult
    {
        /// <summary>
        /// Gets a value indicating whether the archive file is corrupted.
        /// </summary>
        public bool IsCorrupted { get; }

        /// <summary>
        /// Gets a value indicating whether the archive or any of its entries is encrypted/password protected.
        /// </summary>
        public bool IsEncrypted { get; }

        /// <summary>
        /// Gets a value indicating whether the archive contains executable or system files.
        /// </summary>
        public bool ContainsExecutable { get; }

        /// <summary>
        /// Gets a value indicating whether the archive contains Office macro binaries (vbaProject.bin).
        /// </summary>
        public bool ContainsMacros { get; }

        /// <summary>
        /// Gets the detected modern Office format extension if this archive is actually a DOCX, XLSX, or PPTX file.
        /// </summary>
        public string DetectedOfficeFormat { get; }

        /// <summary>
        /// Gets the list of file entry paths found inside the archive.
        /// </summary>
        public IReadOnlyList<string> FileEntries { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ArchiveInspectionResult"/> class.
        /// </summary>
        public ArchiveInspectionResult(
            bool isCorrupted,
            bool isEncrypted,
            bool containsExecutable,
            bool containsMacros,
            string detectedOfficeFormat,
            IReadOnlyList<string> fileEntries)
        {
            IsCorrupted = isCorrupted;
            IsEncrypted = isEncrypted;
            ContainsExecutable = containsExecutable;
            ContainsMacros = containsMacros;
            DetectedOfficeFormat = detectedOfficeFormat;
            FileEntries = fileEntries ?? Array.Empty<string>();
        }

        /// <summary>
        /// Creates a result indicating that archive inspection failed due to corruption.
        /// </summary>
        public static ArchiveInspectionResult Corrupted() => new ArchiveInspectionResult(true, false, false, false, null, null);
    }
}
