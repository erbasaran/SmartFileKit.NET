using System;

namespace SmartFileKit.Domain
{
    /// <summary>
    /// Represents a read-only file size with conversion, arithmetic, and formatting capabilities.
    /// </summary>
    public readonly struct FileSize : IEquatable<FileSize>, IComparable<FileSize>
    {
        private const double BytesInKb = 1024.0;
        private const double BytesInMb = BytesInKb * 1024.0;
        private const double BytesInGb = BytesInMb * 1024.0;
        private const double BytesInTb = BytesInGb * 1024.0;

        /// <summary>
        /// The size in bytes.
        /// </summary>
        public long Bytes { get; }

        /// <summary>
        /// Gets the size in Kilobytes (KB).
        /// </summary>
        public double Kilobytes => Bytes / BytesInKb;

        /// <summary>
        /// Gets the size in Megabytes (MB).
        /// </summary>
        public double Megabytes => Bytes / BytesInMb;

        /// <summary>
        /// Gets the size in Gigabytes (GB).
        /// </summary>
        public double Gigabytes => Bytes / BytesInGb;

        /// <summary>
        /// Gets the size in Terabytes (TB).
        /// </summary>
        public double Terabytes => Bytes / BytesInTb;

        /// <summary>
        /// Initializes a new instance of the <see cref="FileSize"/> struct.
        /// </summary>
        /// <param name="bytes">The size in bytes.</param>
        public FileSize(long bytes)
        {
            Bytes = bytes < 0 ? throw new ArgumentOutOfRangeException(nameof(bytes), "File size cannot be negative.") : bytes;
        }

        public static FileSize FromBytes(long bytes) => new FileSize(bytes);
        public static FileSize FromKilobytes(double value) => new FileSize((long)(value * BytesInKb));
        public static FileSize FromMegabytes(double value) => new FileSize((long)(value * BytesInMb));
        public static FileSize FromGigabytes(double value) => new FileSize((long)(value * BytesInGb));
        public static FileSize FromTerabytes(double value) => new FileSize((long)(value * BytesInTb));

        /// <summary>
        /// Formats the file size to a human-readable string using the default precision of 2 decimal places.
        /// </summary>
        public override string ToString() => ToString(2);

        /// <summary>
        /// Formats the file size to a human-readable string with custom decimal precision.
        /// </summary>
        /// <param name="precision">Number of decimal places (between 0 and 99).</param>
        public string ToString(int precision)
        {
            if (precision < 0 || precision > 99)
                throw new ArgumentOutOfRangeException(nameof(precision), "Precision must be between 0 and 99.");

            string format = $"F{precision}";

            if (Bytes >= 1099511627776L) // 1 TB
                return $"{Terabytes.ToString(format, System.Globalization.CultureInfo.InvariantCulture)} TB";
            if (Bytes >= 1073741824L) // 1 GB
                return $"{Gigabytes.ToString(format, System.Globalization.CultureInfo.InvariantCulture)} GB";
            if (Bytes >= 1048576L) // 1 MB
                return $"{Megabytes.ToString(format, System.Globalization.CultureInfo.InvariantCulture)} MB";
            if (Bytes >= 1024L) // 1 KB
                return $"{Kilobytes.ToString(format, System.Globalization.CultureInfo.InvariantCulture)} KB";

            return $"{Bytes} Bytes";
        }

        #region Equality and Comparison

        public bool Equals(FileSize other) => Bytes == other.Bytes;

        public override bool Equals(object obj) => obj is FileSize other && Equals(other);

        public override int GetHashCode() => Bytes.GetHashCode();

        public int CompareTo(FileSize other) => Bytes.CompareTo(other.Bytes);

        public static bool operator ==(FileSize left, FileSize right) => left.Equals(right);

        public static bool operator !=(FileSize left, FileSize right) => !left.Equals(right);

        public static bool operator <(FileSize left, FileSize right) => left.Bytes < right.Bytes;

        public static bool operator >(FileSize left, FileSize right) => left.Bytes > right.Bytes;

        public static bool operator <=(FileSize left, FileSize right) => left.Bytes <= right.Bytes;

        public static bool operator >=(FileSize left, FileSize right) => left.Bytes >= right.Bytes;

        #endregion

        #region Arithmetic Operators

        public static FileSize operator +(FileSize left, FileSize right) => new FileSize(left.Bytes + right.Bytes);

        public static FileSize operator -(FileSize left, FileSize right) => new FileSize(left.Bytes - right.Bytes);

        public static FileSize operator *(FileSize left, double multiplier) => new FileSize((long)(left.Bytes * multiplier));

        public static FileSize operator /(FileSize left, double divisor) => new FileSize((long)(left.Bytes / divisor));

        #endregion
    }
}
