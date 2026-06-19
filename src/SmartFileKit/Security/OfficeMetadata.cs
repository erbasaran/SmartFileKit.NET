using System;
using System.IO;
using System.IO.Compression;
using System.Xml;

namespace SmartFileKit.Security
{
    /// <summary>
    /// Provides low-overhead, dependency-free metadata parsing for OpenXML Office files (docx, xlsx, pptx).
    /// </summary>
    public static class OfficeMetadata
    {
        /// <summary>
        /// Reads core and extended properties from seekable Office files (.docx, .xlsx, .pptx) without external libraries.
        /// Does not close the stream and resets its position if seekable.
        /// </summary>
        public static OfficeMetadataResult Read(Stream stream)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));

            long originalPosition = 0;
            bool canSeek = stream.CanSeek;
            if (canSeek)
            {
                originalPosition = stream.Position;
            }

            string author = null;
            string title = null;
            DateTime? createdDate = null;
            DateTime? modifiedDate = null;
            string company = null;
            bool isValid = false;

            try
            {
                // ZipArchive requires seekable stream. We leave open to allow downstream reuse.
                using (var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true))
                {
                    // 1. Read docProps/core.xml for author, title, and dates
                    var coreEntry = archive.GetEntry("docProps/core.xml");
                    if (coreEntry != null)
                    {
                        isValid = true;
                        using (var entryStream = coreEntry.Open())
                        {
                            var doc = new XmlDocument();
                            doc.Load(entryStream);

                            var nsmgr = new XmlNamespaceManager(doc.NameTable);
                            nsmgr.AddNamespace("cp", "http://schemas.openxmlformats.org/package/2006/metadata/core-properties");
                            nsmgr.AddNamespace("dc", "http://purl.org/dc/elements/1.1/");
                            nsmgr.AddNamespace("dcterms", "http://purl.org/dc/terms/");

                            author = doc.SelectSingleNode("//dc:creator", nsmgr)?.InnerText;
                            title = doc.SelectSingleNode("//dc:title", nsmgr)?.InnerText;

                            string createdStr = doc.SelectSingleNode("//dcterms:created", nsmgr)?.InnerText;
                            if (DateTime.TryParse(createdStr, out DateTime created))
                            {
                                createdDate = created;
                            }

                            string modifiedStr = doc.SelectSingleNode("//dcterms:modified", nsmgr)?.InnerText;
                            if (DateTime.TryParse(modifiedStr, out DateTime modified))
                            {
                                modifiedDate = modified;
                            }
                        }
                    }

                    // 2. Read docProps/app.xml for company
                    var appEntry = archive.GetEntry("docProps/app.xml");
                    if (appEntry != null)
                    {
                        using (var entryStream = appEntry.Open())
                        {
                            var doc = new XmlDocument();
                            doc.Load(entryStream);

                            var nsmgr = new XmlNamespaceManager(doc.NameTable);
                            nsmgr.AddNamespace("ep", "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties");

                            company = doc.SelectSingleNode("//ep:Company", nsmgr)?.InnerText;
                            if (string.IsNullOrEmpty(company))
                            {
                                company = doc.SelectSingleNode("//*[local-name()='Company']")?.InnerText;
                            }
                        }
                    }
                }
            }
            catch
            {
                return OfficeMetadataResult.Invalid();
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
                        // Ignore position reset failure
                    }
                }
            }

            if (!isValid) return OfficeMetadataResult.Invalid();

            return new OfficeMetadataResult(author, title, createdDate, modifiedDate, company, true);
        }
    }
}
