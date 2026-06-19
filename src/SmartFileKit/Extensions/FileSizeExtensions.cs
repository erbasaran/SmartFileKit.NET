using SmartFileKit.Domain;

namespace SmartFileKit
{
    /// <summary>
    /// Fluent extension methods for converting numeric values into FileSize objects.
    /// </summary>
    public static class FileSizeExtensions
    {
        /// <summary>
        /// Converts a long representing bytes to a FileSize object.
        /// </summary>
        public static FileSize ToFileSize(this long bytes) => new FileSize(bytes);

        /// <summary>
        /// Converts an int representing bytes to a FileSize object.
        /// </summary>
        public static FileSize ToFileSize(this int bytes) => new FileSize(bytes);

        /// <summary>
        /// Creates a FileSize representing the specified value in Kilobytes.
        /// </summary>
        public static FileSize KB(this int val) => FileSize.FromKilobytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Kilobytes.
        /// </summary>
        public static FileSize KB(this long val) => FileSize.FromKilobytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Kilobytes.
        /// </summary>
        public static FileSize KB(this double val) => FileSize.FromKilobytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Megabytes.
        /// </summary>
        public static FileSize MB(this int val) => FileSize.FromMegabytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Megabytes.
        /// </summary>
        public static FileSize MB(this long val) => FileSize.FromMegabytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Megabytes.
        /// </summary>
        public static FileSize MB(this double val) => FileSize.FromMegabytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Gigabytes.
        /// </summary>
        public static FileSize GB(this int val) => FileSize.FromGigabytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Gigabytes.
        /// </summary>
        public static FileSize GB(this long val) => FileSize.FromGigabytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Gigabytes.
        /// </summary>
        public static FileSize GB(this double val) => FileSize.FromGigabytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Terabytes.
        /// </summary>
        public static FileSize TB(this int val) => FileSize.FromTerabytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Terabytes.
        /// </summary>
        public static FileSize TB(this long val) => FileSize.FromTerabytes(val);

        /// <summary>
        /// Creates a FileSize representing the specified value in Terabytes.
        /// </summary>
        public static FileSize TB(this double val) => FileSize.FromTerabytes(val);
    }
}
