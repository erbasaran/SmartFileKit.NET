using System;
using System.Collections.Generic;
using System.Text;
using SmartFileKit.Domain;

namespace SmartFileKit.Detection
{
    /// <summary>
    /// Exposes the internal file signature registry for debugging, documentation, and external integrations.
    /// </summary>
    public static class FileSignatureDatabase
    {
        /// <summary>
        /// Retrieves all registered file format specifications.
        /// </summary>
        public static IReadOnlyList<FileFormatInfo> GetAll()
        {
            return FileFormatRegistry.Formats.AsReadOnly();
        }

        /// <summary>
        /// Exports the internal signatures database as a formatted JSON string without external dependencies.
        /// </summary>
        public static string ExportJson()
        {
            var sb = new StringBuilder();
            sb.Append("[\n");
            var formats = FileFormatRegistry.Formats;
            for (int i = 0; i < formats.Count; i++)
            {
                var format = formats[i];
                sb.Append("  {\n");
                sb.Append($"    \"extension\": \"{format.Extension}\",\n");
                sb.Append($"    \"mimeType\": \"{format.MimeType}\",\n");
                sb.Append($"    \"category\": \"{format.Category}\",\n");
                sb.Append("    \"signatures\": [\n");

                var sigs = format.Signatures;
                for (int j = 0; j < sigs.Count; j++)
                {
                    var sig = sigs[j];
                    sb.Append("      {\n");
                    sb.Append($"        \"offset\": {sig.Offset},\n");
                    sb.Append("        \"magicBytes\": \"");
                    sb.Append(BitConverter.ToString(sig.MagicBytes).Replace("-", " "));
                    sb.Append("\"\n");
                    sb.Append("      }");
                    if (j < sigs.Count - 1) sb.Append(",");
                    sb.Append("\n");
                }

                sb.Append("    ]\n");
                sb.Append("  }");
                if (i < formats.Count - 1) sb.Append(",");
                sb.Append("\n");
            }
            sb.Append("]");
            return sb.ToString();
        }
    }
}
