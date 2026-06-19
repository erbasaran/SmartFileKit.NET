namespace SmartFileKit.Domain
{
    /// <summary>
    /// Represents the high-level classification category of a file.
    /// </summary>
    public enum FileCategory
    {
        /// <summary>
        /// Unknown or unclassified file type.
        /// </summary>
        Unknown,

        /// <summary>
        /// Image files (e.g., JPEG, PNG, GIF, BMP, WEBP, TIFF, SVG, ICO, HEIC).
        /// </summary>
        Image,

        /// <summary>
        /// Document files (e.g., PDF, DOC, DOCX, RTF, TXT, CSV).
        /// </summary>
        Document,

        /// <summary>
        /// Spreadsheet files (e.g., XLS, XLSX).
        /// </summary>
        Spreadsheet,

        /// <summary>
        /// Presentation files (e.g., PPT, PPTX).
        /// </summary>
        Presentation,

        /// <summary>
        /// Compressed archives (e.g., ZIP, RAR, 7Z, TAR, GZ, BZ2).
        /// </summary>
        Archive,

        /// <summary>
        /// Audio files (e.g., MP3, WAV, OGG, AAC, FLAC).
        /// </summary>
        Audio,

        /// <summary>
        /// Video files (e.g., MP4, AVI, MOV, MKV, FLV, WMV, MPEG, MPG, WEBM).
        /// </summary>
        Video,

        /// <summary>
        /// Executable files, DLLs, shell scripts, and system binaries (e.g., EXE, DLL, SYS, BAT, SH, MSI, BIN).
        /// </summary>
        Executable,

        /// <summary>
        /// Web-related files (e.g., HTML).
        /// </summary>
        Web,

        /// <summary>
        /// Data serialization formats (e.g., JSON, XML).
        /// </summary>
        Data
    }
}
