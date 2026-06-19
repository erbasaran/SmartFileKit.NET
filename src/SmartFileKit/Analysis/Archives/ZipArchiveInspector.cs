using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace SmartFileKit.Analysis.Archives
{
    /// <summary>
    /// Inspects ZIP-based archives (including DOCX, XLSX, PPTX files) for inner entries and security checks.
    /// </summary>
    public class ZipArchiveInspector : IArchiveInspector
    {
        private static readonly HashSet<string> ExecutableExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".sh", ".lnk", ".vbs", ".js",
            ".scr", ".pif", ".cpl", ".wsf", ".jar", ".py", ".ps1", ".hta"
        };

        /// <summary>
        /// Determines whether this inspector supports the specified file extension.
        /// </summary>
        public bool CanInspect(string extension)
        {
            if (string.IsNullOrEmpty(extension)) return false;
            string ext = extension.Trim().ToLowerInvariant();
            if (!ext.StartsWith(".", StringComparison.Ordinal)) ext = "." + ext;
            return ext == ".zip" || ext == ".docx" || ext == ".xlsx" || ext == ".pptx";
        }

        /// <summary>
        /// Inspects the ZIP archive stream for encryption, executables, corruption, or Office formats.
        /// </summary>
        public ArchiveInspectionResult Inspect(Stream stream)
        {
            if (stream == null) return ArchiveInspectionResult.Corrupted();

            long originalPosition = 0;
            bool canSeek = stream.CanSeek;
            if (canSeek)
            {
                originalPosition = stream.Position;
            }

            var entries = new List<string>();
            bool containsExecutable = false;
            bool containsMacros = false;
            bool isEncrypted = false;
            bool isCorrupted = false;
            string detectedOfficeFormat = null;

            try
            {
                using (var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true))
                {
                    foreach (var entry in archive.Entries)
                    {
                        entries.Add(entry.FullName);

                        // 1. Check for Office XML structures
                        if (entry.FullName.Equals("word/document.xml", StringComparison.OrdinalIgnoreCase))
                        {
                            detectedOfficeFormat = "docx";
                        }
                        else if (entry.FullName.Equals("xl/workbook.xml", StringComparison.OrdinalIgnoreCase))
                        {
                            detectedOfficeFormat = "xlsx";
                        }
                        else if (entry.FullName.Equals("ppt/presentation.xml", StringComparison.OrdinalIgnoreCase))
                        {
                            detectedOfficeFormat = "pptx";
                        }

                        // 2. Check for executable files inside archive
                        string ext = Path.GetExtension(entry.FullName);
                        if (!string.IsNullOrEmpty(ext) && ExecutableExtensions.Contains(ext))
                        {
                            containsExecutable = true;
                        }

                        // 3. Check for macro binaries (VBA project)
                        if (entry.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                        {
                            containsMacros = true;
                        }

                        // 4. Inspect if entry is encrypted
                        if (!entry.FullName.EndsWith("/", StringComparison.Ordinal) && !isEncrypted)
                        {
                            try
                            {
                                using (var entryStream = entry.Open())
                                {
                                    // Reading a single byte checks if decryption is required
                                    entryStream.ReadByte();
                                }
                            }
                            catch (InvalidDataException ex) when (ex.Message.IndexOf("password", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                                  ex.Message.IndexOf("encryption", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                                  ex.Message.IndexOf("decrypt", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                isEncrypted = true;
                            }
                            catch (InvalidDataException)
                            {
                                isEncrypted = true; // Assumed encrypted or unsupported structure
                            }
                            catch
                            {
                                // Other errors are ignored for encryption check
                            }
                        }
                    }
                }
            }
            catch
            {
                isCorrupted = true;
            }
            finally
            {
                if (canSeek)
                {
                    try
                    {
                        stream.Position = originalPosition;
                    }
                    catch
                    {
                        // Ignore seek reset errors
                    }
                }
            }

            if (isCorrupted)
            {
                return ArchiveInspectionResult.Corrupted();
            }

            return new ArchiveInspectionResult(
                isCorrupted: false,
                isEncrypted: isEncrypted,
                containsExecutable: containsExecutable,
                containsMacros: containsMacros,
                detectedOfficeFormat: detectedOfficeFormat,
                fileEntries: entries.AsReadOnly());
        }
    }
}
