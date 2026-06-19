using SmartFileKit.Detection;
using SmartFileKit.Domain;
using System.IO;

namespace SmartFileKit
{
    /// <summary>
    /// Provides simple, developer-friendly static entry points to detect file categories, formats, and types.
    /// </summary>
    public static class FileType
    {
        /// <summary>
        /// Detects the file format information from a stream.
        /// </summary>
        public static FileFormatInfo GetFormat(Stream stream) => FormatDetector.Detect(stream);

        /// <summary>
        /// Detects the file format information from a byte array.
        /// </summary>
        public static FileFormatInfo GetFormat(byte[] buffer) => FormatDetector.Detect(buffer);

        /// <summary>
        /// Detects the file format information from a file path.
        /// </summary>
        public static FileFormatInfo GetFormat(string filePath) => FormatDetector.Detect(filePath);

        /// <summary>
        /// Gets the high-level classification category of a stream.
        /// </summary>
        public static FileCategory GetCategory(Stream stream) => GetFormat(stream)?.Category ?? FileCategory.Unknown;

        /// <summary>
        /// Gets the high-level classification category of a byte array.
        /// </summary>
        public static FileCategory GetCategory(byte[] buffer) => GetFormat(buffer)?.Category ?? FileCategory.Unknown;

        /// <summary>
        /// Gets the high-level classification category of a file path.
        /// </summary>
        public static FileCategory GetCategory(string filePath) => GetFormat(filePath)?.Category ?? FileCategory.Unknown;

        /// <summary>
        /// Determines if the file stream is classified as an Image.
        /// </summary>
        public static bool IsImage(Stream stream) => GetCategory(stream) == FileCategory.Image;

        /// <summary>
        /// Determines if the byte array is classified as an Image.
        /// </summary>
        public static bool IsImage(byte[] buffer) => GetCategory(buffer) == FileCategory.Image;

        /// <summary>
        /// Determines if the file path is classified as an Image.
        /// </summary>
        public static bool IsImage(string filePath) => GetCategory(filePath) == FileCategory.Image;

        /// <summary>
        /// Determines if the file stream is classified as a Document.
        /// </summary>
        public static bool IsDocument(Stream stream) => GetCategory(stream) == FileCategory.Document;

        /// <summary>
        /// Determines if the byte array is classified as a Document.
        /// </summary>
        public static bool IsDocument(byte[] buffer) => GetCategory(buffer) == FileCategory.Document;

        /// <summary>
        /// Determines if the file path is classified as a Document.
        /// </summary>
        public static bool IsDocument(string filePath) => GetCategory(filePath) == FileCategory.Document;

        /// <summary>
        /// Determines if the file stream is classified as a Spreadsheet.
        /// </summary>
        public static bool IsSpreadsheet(Stream stream) => GetCategory(stream) == FileCategory.Spreadsheet;

        /// <summary>
        /// Determines if the byte array is classified as a Spreadsheet.
        /// </summary>
        public static bool IsSpreadsheet(byte[] buffer) => GetCategory(buffer) == FileCategory.Spreadsheet;

        /// <summary>
        /// Determines if the file path is classified as a Spreadsheet.
        /// </summary>
        public static bool IsSpreadsheet(string filePath) => GetCategory(filePath) == FileCategory.Spreadsheet;

        /// <summary>
        /// Determines if the file stream is classified as a Presentation.
        /// </summary>
        public static bool IsPresentation(Stream stream) => GetCategory(stream) == FileCategory.Presentation;

        /// <summary>
        /// Determines if the byte array is classified as a Presentation.
        /// </summary>
        public static bool IsPresentation(byte[] buffer) => GetCategory(buffer) == FileCategory.Presentation;

        /// <summary>
        /// Determines if the file path is classified as a Presentation.
        /// </summary>
        public static bool IsPresentation(string filePath) => GetCategory(filePath) == FileCategory.Presentation;

        /// <summary>
        /// Determines if the file stream is classified as an Archive.
        /// </summary>
        public static bool IsArchive(Stream stream) => GetCategory(stream) == FileCategory.Archive;

        /// <summary>
        /// Determines if the byte array is classified as an Archive.
        /// </summary>
        public static bool IsArchive(byte[] buffer) => GetCategory(buffer) == FileCategory.Archive;

        /// <summary>
        /// Determines if the file path is classified as an Archive.
        /// </summary>
        public static bool IsArchive(string filePath) => GetCategory(filePath) == FileCategory.Archive;

        /// <summary>
        /// Determines if the file stream is classified as Audio.
        /// </summary>
        public static bool IsAudio(Stream stream) => GetCategory(stream) == FileCategory.Audio;

        /// <summary>
        /// Determines if the byte array is classified as Audio.
        /// </summary>
        public static bool IsAudio(byte[] buffer) => GetCategory(buffer) == FileCategory.Audio;

        /// <summary>
        /// Determines if the file path is classified as Audio.
        /// </summary>
        public static bool IsAudio(string filePath) => GetCategory(filePath) == FileCategory.Audio;

        /// <summary>
        /// Determines if the file stream is classified as Video.
        /// </summary>
        public static bool IsVideo(Stream stream) => GetCategory(stream) == FileCategory.Video;

        /// <summary>
        /// Determines if the byte array is classified as Video.
        /// </summary>
        public static bool IsVideo(byte[] buffer) => GetCategory(buffer) == FileCategory.Video;

        /// <summary>
        /// Determines if the file path is classified as Video.
        /// </summary>
        public static bool IsVideo(string filePath) => GetCategory(filePath) == FileCategory.Video;

        /// <summary>
        /// Determines if the file stream is classified as an Executable/System file.
        /// </summary>
        public static bool IsExecutable(Stream stream) => GetCategory(stream) == FileCategory.Executable;

        /// <summary>
        /// Determines if the byte array is classified as an Executable/System file.
        /// </summary>
        public static bool IsExecutable(byte[] buffer) => GetCategory(buffer) == FileCategory.Executable;

        /// <summary>
        /// Determines if the file path is classified as an Executable/System file.
        /// </summary>
        public static bool IsExecutable(string filePath) => GetCategory(filePath) == FileCategory.Executable;
    }
}
