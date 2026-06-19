using SmartFileKit.Domain;
using System;
using System.Collections.Generic;

namespace SmartFileKit.Detection
{
    /// <summary>
    /// Provides MIME type, extension, and category mapping lookup tables.
    /// </summary>
    public static class MimeMapper
    {
        private static readonly Dictionary<string, string> ExtensionToMime = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, string> MimeToExtension = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, FileCategory> ExtensionToCategory = new Dictionary<string, FileCategory>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, FileCategory> MimeToCategory = new Dictionary<string, FileCategory>(StringComparer.OrdinalIgnoreCase);

        static MimeMapper()
        {
            foreach (var format in FileFormatRegistry.Formats)
            {
                // Extension is already normalized to start with "." and lowercase
                string ext = format.Extension;
                string mime = format.MimeType;
                FileCategory cat = format.Category;

                // Extension -> Mime
                if (!ExtensionToMime.ContainsKey(ext))
                {
                    ExtensionToMime[ext] = mime;
                }

                // Mime -> Extension (primary mapping)
                if (!MimeToExtension.ContainsKey(mime))
                {
                    MimeToExtension[mime] = ext;
                }

                // Extension -> Category
                if (!ExtensionToCategory.ContainsKey(ext))
                {
                    ExtensionToCategory[ext] = cat;
                }

                // Mime -> Category
                if (!MimeToCategory.ContainsKey(mime))
                {
                    MimeToCategory[mime] = cat;
                }
            }
        }

        /// <summary>
        /// Gets the MIME type associated with the given file extension.
        /// </summary>
        /// <param name="extension">The file extension (e.g. ".jpg" or "jpg").</param>
        /// <returns>The MIME type, or "application/octet-stream" if unknown.</returns>
        public static string GetMimeType(string extension)
        {
            if (string.IsNullOrEmpty(extension))
                return "application/octet-stream";

            string key = NormalizeExtension(extension);
            return ExtensionToMime.TryGetValue(key, out string mime) ? mime : "application/octet-stream";
        }

        /// <summary>
        /// Gets the primary extension associated with the given MIME type.
        /// </summary>
        /// <param name="mimeType">The MIME type (e.g. "image/jpeg").</param>
        /// <returns>The extension with dot prefix (e.g. ".jpg"), or empty string if unknown.</returns>
        public static string GetExtension(string mimeType)
        {
            if (string.IsNullOrEmpty(mimeType))
                return string.Empty;

            string key = mimeType.Trim().ToLowerInvariant();
            return MimeToExtension.TryGetValue(key, out string ext) ? ext : string.Empty;
        }

        /// <summary>
        /// Gets the file classification category associated with the given file extension.
        /// </summary>
        /// <param name="extension">The file extension (e.g. ".jpg" or "jpg").</param>
        /// <returns>The classification category.</returns>
        public static FileCategory GetCategory(string extension)
        {
            if (string.IsNullOrEmpty(extension))
                return FileCategory.Unknown;

            string key = NormalizeExtension(extension);
            return ExtensionToCategory.TryGetValue(key, out FileCategory cat) ? cat : FileCategory.Unknown;
        }

        /// <summary>
        /// Gets the file classification category associated with the given MIME type.
        /// </summary>
        /// <param name="mimeType">The MIME type (e.g. "image/jpeg").</param>
        /// <returns>The classification category.</returns>
        public static FileCategory GetCategoryByMimeType(string mimeType)
        {
            if (string.IsNullOrEmpty(mimeType))
                return FileCategory.Unknown;

            string key = mimeType.Trim().ToLowerInvariant();
            return MimeToCategory.TryGetValue(key, out FileCategory cat) ? cat : FileCategory.Unknown;
        }

        private static string NormalizeExtension(string extension)
        {
            string ext = extension.Trim();
            return ext.StartsWith(".", StringComparison.Ordinal) ? ext.ToLowerInvariant() : "." + ext.ToLowerInvariant();
        }
    }
}
