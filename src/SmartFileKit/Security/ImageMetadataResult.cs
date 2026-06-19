namespace SmartFileKit.Security
{
    /// <summary>
    /// Holds image resolution and format metadata extracted by the lightweight reader.
    /// </summary>
    public class ImageMetadataResult
    {
        /// <summary>
        /// Gets the image width in pixels.
        /// </summary>
        public int Width { get; }

        /// <summary>
        /// Gets the image height in pixels.
        /// </summary>
        public int Height { get; }

        /// <summary>
        /// Gets the detected image format (e.g. "PNG", "JPEG", "GIF", "BMP", "WebP").
        /// </summary>
        public string Format { get; }

        /// <summary>
        /// Gets a value indicating whether metadata extraction succeeded.
        /// </summary>
        public bool IsValid { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ImageMetadataResult"/> class.
        /// </summary>
        public ImageMetadataResult(int width, int height, string format, bool isValid)
        {
            Width = width;
            Height = height;
            Format = format ?? string.Empty;
            IsValid = isValid;
        }

        /// <summary>
        /// Returns an invalid metadata result.
        /// </summary>
        public static ImageMetadataResult Invalid() => new ImageMetadataResult(0, 0, null, false);
    }
}
