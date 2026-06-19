using SmartFileKit.Domain;
using System;
using System.Collections.Generic;

namespace SmartFileKit.Detection
{
    internal static class FileFormatRegistry
    {
        public static readonly List<FileFormatInfo> Formats = new List<FileFormatInfo>();

        static FileFormatRegistry()
        {
            #region Images
            Formats.Add(new FileFormatInfo("jpg", "image/jpeg", FileCategory.Image, new[]
            {
                new FileSignature(new byte[] { 0xFF, 0xD8, 0xFF })
            }));

            Formats.Add(new FileFormatInfo("jpeg", "image/jpeg", FileCategory.Image, new[]
            {
                new FileSignature(new byte[] { 0xFF, 0xD8, 0xFF })
            }));

            Formats.Add(new FileFormatInfo("png", "image/png", FileCategory.Image, new[]
            {
                new FileSignature(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A })
            }));

            Formats.Add(new FileFormatInfo("gif", "image/gif", FileCategory.Image, new[]
            {
                new FileSignature(new byte[] { 0x47, 0x49, 0x46, 0x38, 0x37, 0x61 }), // GIF87a
                new FileSignature(new byte[] { 0x47, 0x49, 0x46, 0x38, 0x39, 0x61 })  // GIF89a
            }));

            Formats.Add(new FileFormatInfo("bmp", "image/bmp", FileCategory.Image, new[]
            {
                new FileSignature(new byte[] { 0x42, 0x4D }) // BM
            }));

            Formats.Add(new FileFormatInfo("webp", "image/webp", FileCategory.Image, new[]
            {
                // RIFF....WEBP (matches RIFF at 0 and WEBP at 8)
                new FileSignature(
                    new byte[] { 0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50 },
                    0,
                    new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF }
                )
            }));

            Formats.Add(new FileFormatInfo("tiff", "image/tiff", FileCategory.Image, new[]
            {
                new FileSignature(new byte[] { 0x49, 0x49, 0x2A, 0x00 }), // Little Endian
                new FileSignature(new byte[] { 0x4D, 0x4D, 0x00, 0x2A })  // Big Endian
            }));

            Formats.Add(new FileFormatInfo("svg", "image/svg+xml", FileCategory.Image, extraValidator: IsSvg));

            Formats.Add(new FileFormatInfo("ico", "image/x-icon", FileCategory.Image, new[]
            {
                new FileSignature(new byte[] { 0x00, 0x00, 0x01, 0x00 })
            }));

            Formats.Add(new FileFormatInfo("heic", "image/heic", FileCategory.Image, new[]
            {
                new FileSignature(new byte[] { 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63 }, 4), // ftypheic
                new FileSignature(new byte[] { 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x78 }, 4), // ftypheix
                new FileSignature(new byte[] { 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x76, 0x63 }, 4), // ftyphevc
                new FileSignature(new byte[] { 0x66, 0x74, 0x79, 0x70, 0x6D, 0x69, 0x66, 0x31 }, 4)  // ftypmif1
            }));
            #endregion

            #region Documents
            Formats.Add(new FileFormatInfo("pdf", "application/pdf", FileCategory.Document, new[]
            {
                new FileSignature(new byte[] { 0x25, 0x50, 0x44, 0x46 }) // %PDF
            }));

            Formats.Add(new FileFormatInfo("rtf", "application/rtf", FileCategory.Document, new[]
            {
                new FileSignature(new byte[] { 0x7B, 0x5C, 0x72, 0x74, 0x66 }) // {\rtf
            }));


            // Legacy Office Formats (OLE CF container format)
            Formats.Add(new FileFormatInfo("doc", "application/msword", FileCategory.Document, new[]
            {
                new FileSignature(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })
            }));

            Formats.Add(new FileFormatInfo("xls", "application/vnd.ms-excel", FileCategory.Spreadsheet, new[]
            {
                new FileSignature(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })
            }));

            Formats.Add(new FileFormatInfo("ppt", "application/vnd.ms-powerpoint", FileCategory.Presentation, new[]
            {
                new FileSignature(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 })
            }));

            // Office OpenXML formats (ZIP based)
            Formats.Add(new FileFormatInfo("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", FileCategory.Document, new[]
            {
                new FileSignature(new byte[] { 0x50, 0x4B, 0x03, 0x04 }) // PK ZIP header
            }, IsDocx));

            Formats.Add(new FileFormatInfo("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", FileCategory.Spreadsheet, new[]
            {
                new FileSignature(new byte[] { 0x50, 0x4B, 0x03, 0x04 })
            }, IsXlsx));

            Formats.Add(new FileFormatInfo("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", FileCategory.Presentation, new[]
            {
                new FileSignature(new byte[] { 0x50, 0x4B, 0x03, 0x04 })
            }, IsPptx));
            #endregion

            #region Archives
            Formats.Add(new FileFormatInfo("zip", "application/zip", FileCategory.Archive, new[]
            {
                new FileSignature(new byte[] { 0x50, 0x4B, 0x03, 0x04 })
            }, IsGenericZip)); // Custom validator checks that it is NOT docx/xlsx/pptx

            Formats.Add(new FileFormatInfo("rar", "application/vnd.rar", FileCategory.Archive, new[]
            {
                new FileSignature(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 }), // Rar! v5
                new FileSignature(new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 }) // Rar! v4
            }));

            Formats.Add(new FileFormatInfo("7z", "application/x-7z-compressed", FileCategory.Archive, new[]
            {
                new FileSignature(new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C })
            }));

            Formats.Add(new FileFormatInfo("tar", "application/x-tar", FileCategory.Archive, new[]
            {
                new FileSignature(new byte[] { 0x75, 0x73, 0x74, 0x61, 0x72 }, 257) // ustar at offset 257
            }));

            Formats.Add(new FileFormatInfo("gz", "application/gzip", FileCategory.Archive, new[]
            {
                new FileSignature(new byte[] { 0x1F, 0x8B })
            }));

            Formats.Add(new FileFormatInfo("bz2", "application/x-bzip2", FileCategory.Archive, new[]
            {
                new FileSignature(new byte[] { 0x42, 0x5A, 0x68 }) // BZh
            }));
            #endregion

            #region Videos
            Formats.Add(new FileFormatInfo("mp4", "video/mp4", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x66, 0x74, 0x79, 0x70 }, 4) // ftyp at offset 4
            }));

            Formats.Add(new FileFormatInfo("avi", "video/x-msvideo", FileCategory.Video, new[]
            {
                // RIFF....AVI  (matches RIFF at 0 and AVI  at 8)
                new FileSignature(
                    new byte[] { 0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x41, 0x56, 0x49, 0x20 },
                    0,
                    new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF }
                )
            }));

            Formats.Add(new FileFormatInfo("mov", "video/quicktime", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20 }, 4), // ftypqt  
                new FileSignature(new byte[] { 0x6D, 0x6F, 0x6F, 0x76 }, 4) // moov
            }));

            Formats.Add(new FileFormatInfo("mkv", "video/x-matroska", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x1A, 0x45, 0xDF, 0xA3 }) // EBML header
            }, IsMkv));

            Formats.Add(new FileFormatInfo("webm", "video/webm", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x1A, 0x45, 0xDF, 0xA3 }) // EBML header
            }, IsWebm));

            Formats.Add(new FileFormatInfo("flv", "video/x-flv", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x46, 0x4C, 0x56, 0x01 }) // FLV\x01
            }));

            Formats.Add(new FileFormatInfo("wmv", "video/x-ms-wmv", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11 }) // ASF header
            }));

            Formats.Add(new FileFormatInfo("mpeg", "video/mpeg", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x00, 0x00, 0x01, 0xBA }),
                new FileSignature(new byte[] { 0x00, 0x00, 0x01, 0xB3 })
            }));

            Formats.Add(new FileFormatInfo("mpg", "video/mpeg", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x00, 0x00, 0x01, 0xBA }),
                new FileSignature(new byte[] { 0x00, 0x00, 0x01, 0xB3 })
            }));

            Formats.Add(new FileFormatInfo("mpeg", "video/mpeg", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x00, 0x00, 0x01, 0xBA }),
                new FileSignature(new byte[] { 0x00, 0x00, 0x01, 0xB3 })
            }));

            Formats.Add(new FileFormatInfo("mpg", "video/mpeg", FileCategory.Video, new[]
            {
                new FileSignature(new byte[] { 0x00, 0x00, 0x01, 0xBA }),
                new FileSignature(new byte[] { 0x00, 0x00, 0x01, 0xB3 })
            }));
            #endregion

            #region Audio
            Formats.Add(new FileFormatInfo("mp3", "audio/mpeg", FileCategory.Audio, new[]
            {
                new FileSignature(new byte[] { 0x49, 0x44, 0x33 }), // ID3
                new FileSignature(new byte[] { 0xFF, 0xE0 }, 0, new byte[] { 0xFF, 0xE0 }) // MPEG audio frame sync
            }));

            Formats.Add(new FileFormatInfo("wav", "audio/wav", FileCategory.Audio, new[]
            {
                // RIFF....WAVE (matches RIFF at 0 and WAVE at 8)
                new FileSignature(
                    new byte[] { 0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45 },
                    0,
                    new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF }
                )
            }));

            Formats.Add(new FileFormatInfo("ogg", "audio/ogg", FileCategory.Audio, new[]
            {
                new FileSignature(new byte[] { 0x4F, 0x67, 0x67, 0x53 }) // OggS
            }));

            Formats.Add(new FileFormatInfo("flac", "audio/flac", FileCategory.Audio, new[]
            {
                new FileSignature(new byte[] { 0x66, 0x4C, 0x61, 0x43 }) // fLaC
            }));

            Formats.Add(new FileFormatInfo("aac", "audio/aac", FileCategory.Audio, new[]
            {
                new FileSignature(new byte[] { 0xFF, 0xF0 }, 0, new byte[] { 0xFF, 0xF0 }) // ADTS sync word
            }));
            #endregion

            #region Executables and System Files
            Formats.Add(new FileFormatInfo("exe", "application/x-msdownload", FileCategory.Executable, new[]
            {
                new FileSignature(new byte[] { 0x4D, 0x5A }) // MZ
            }));

            Formats.Add(new FileFormatInfo("dll", "application/x-msdownload", FileCategory.Executable, new[]
            {
                new FileSignature(new byte[] { 0x4D, 0x5A }) // MZ
            }));

            Formats.Add(new FileFormatInfo("sys", "application/octet-stream", FileCategory.Executable, new[]
            {
                new FileSignature(new byte[] { 0x4D, 0x5A }) // MZ
            }));

            Formats.Add(new FileFormatInfo("msi", "application/x-msi", FileCategory.Executable, new[]
            {
                new FileSignature(new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }) // OLE CF
            }));

            Formats.Add(new FileFormatInfo("bat", "application/x-bat", FileCategory.Executable, extraValidator: IsBat));

            Formats.Add(new FileFormatInfo("sh", "application/x-sh", FileCategory.Executable, new[]
            {
                new FileSignature(new byte[] { 0x23, 0x21 }) // #! (shebang)
            }));

            Formats.Add(new FileFormatInfo("bin", "application/octet-stream", FileCategory.Executable));
            #endregion

            #region Web and Data Files
            Formats.Add(new FileFormatInfo("json", "application/json", FileCategory.Data, extraValidator: IsJson));

            Formats.Add(new FileFormatInfo("xml", "application/xml", FileCategory.Data, extraValidator: IsXml));

            Formats.Add(new FileFormatInfo("html", "text/html", FileCategory.Web, extraValidator: IsHtml));

            Formats.Add(new FileFormatInfo("csv", "text/csv", FileCategory.Document, extraValidator: IsCsv));

            Formats.Add(new FileFormatInfo("txt", "text/plain", FileCategory.Document, extraValidator: IsText));
            #endregion
        }

        #region Custom Content Validators

        private static bool IsSvg(byte[] buffer)
        {
            if (!IsText(buffer)) return false;

            int idx = GetStartAfterBomAndWhitespace(buffer);
            if (idx >= buffer.Length) return false;

            if (idx + 3 < buffer.Length &&
                buffer[idx] == '<' && buffer[idx + 1] == 's' && buffer[idx + 2] == 'v' && buffer[idx + 3] == 'g')
            {
                return true;
            }

            if (idx + 4 < buffer.Length &&
                buffer[idx] == '<' && buffer[idx + 1] == '?' && buffer[idx + 2] == 'x' && buffer[idx + 3] == 'm' && buffer[idx + 4] == 'l')
            {
                return ContainsAsciiIgnoreCase(buffer, "<svg");
            }

            return false;
        }

        private static bool IsDocx(byte[] buffer)
        {
            return ContainsAscii(buffer, "word/");
        }

        private static bool IsXlsx(byte[] buffer)
        {
            return ContainsAscii(buffer, "xl/");
        }

        private static bool IsPptx(byte[] buffer)
        {
            return ContainsAscii(buffer, "ppt/");
        }

        private static bool IsGenericZip(byte[] buffer)
        {
            // Must start with PK, but should NOT be docx, xlsx, or pptx
            return !IsDocx(buffer) && !IsXlsx(buffer) && !IsPptx(buffer);
        }

        private static bool IsMkv(byte[] buffer)
        {
            return ContainsAscii(buffer, "matroska");
        }

        private static bool IsWebm(byte[] buffer)
        {
            return ContainsAscii(buffer, "webm");
        }

        private static bool IsBat(byte[] buffer)
        {
            if (!IsText(buffer)) return false;
            return ContainsAsciiIgnoreCase(buffer, "@ECHO OFF") ||
                   ContainsAsciiIgnoreCase(buffer, "REM ") ||
                   ContainsAsciiIgnoreCase(buffer, "SET ");
        }

        private static bool IsJson(byte[] buffer)
        {
            int idx = GetStartAfterBomAndWhitespace(buffer);
            if (idx >= buffer.Length) return false;
            byte b = buffer[idx];
            return b == '{' || b == '[';
        }

        private static bool IsXml(byte[] buffer)
        {
            int idx = GetStartAfterBomAndWhitespace(buffer);
            if (idx >= buffer.Length) return false;

            byte b = buffer[idx];
            if (b == '<')
            {
                if (idx + 4 < buffer.Length &&
                    buffer[idx + 1] == '?' && buffer[idx + 2] == 'x' && buffer[idx + 3] == 'm' && buffer[idx + 4] == 'l')
                    return true;

                if (idx + 1 < buffer.Length)
                {
                    char next = (char)buffer[idx + 1];
                    return char.IsLetter(next) || next == '/' || next == '!' || next == '?';
                }
            }
            return false;
        }

        private static bool IsHtml(byte[] buffer)
        {
            if (!IsText(buffer)) return false;
            return ContainsAsciiIgnoreCase(buffer, "<!DOCTYPE HTML") ||
                   ContainsAsciiIgnoreCase(buffer, "<HTML") ||
                   ContainsAsciiIgnoreCase(buffer, "<BODY") ||
                   ContainsAsciiIgnoreCase(buffer, "<HEAD");
        }

        private static bool IsText(byte[] buffer)
        {
            if (buffer == null || buffer.Length == 0) return false;

            // Check BOMs
            if (buffer.Length >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) return true;
            if (buffer.Length >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE) return true;
            if (buffer.Length >= 2 && buffer[0] == 0xFE && buffer[1] == 0xFF) return true;

            int limit = Math.Min(buffer.Length, 512);
            for (int i = 0; i < limit; i++)
            {
                byte b = buffer[i];
                if (b == 0) return false; // Binary files contain 0
                if (b < 32 && b != 9 && b != 10 && b != 13 && b != 26) // Allow Tab, LF, CR, EOF
                    return false;
            }
            return true;
        }

        private static bool IsCsv(byte[] buffer)
        {
            if (!IsText(buffer)) return false;
            int limit = Math.Min(buffer.Length, 1024);
            for (int i = 0; i < limit; i++)
            {
                byte b = buffer[i];
                if (b == ',' || b == ';' || b == '\t')
                    return true;
            }
            return false;
        }

        #endregion

        #region Pattern Matching Helpers

        private static int GetStartAfterBomAndWhitespace(byte[] buffer)
        {
            if (buffer == null || buffer.Length == 0) return 0;

            int idx = 0;
            // UTF-8 BOM
            if (buffer.Length >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
            {
                idx = 3;
            }
            // UTF-16 BOMs
            else if (buffer.Length >= 2 &&
                     ((buffer[0] == 0xFF && buffer[1] == 0xFE) || (buffer[0] == 0xFE && buffer[1] == 0xFF)))
            {
                idx = 2;
            }

            while (idx < buffer.Length)
            {
                byte b = buffer[idx];
                if (b == 0) return idx;
                if (b == ' ' || b == '\t' || b == '\r' || b == '\n')
                {
                    idx++;
                    continue;
                }
                break;
            }
            return idx;
        }

        private static int IndexOfAscii(byte[] array, string pattern)
        {
            if (array == null || string.IsNullOrEmpty(pattern) || array.Length < pattern.Length)
                return -1;

            for (int i = 0; i <= array.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (array[i + j] != (byte)pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        private static bool ContainsAscii(byte[] buffer, string value)
        {
            return IndexOfAscii(buffer, value) >= 0;
        }

        private static bool ContainsAsciiIgnoreCase(byte[] buffer, string pattern)
        {
            if (buffer == null || string.IsNullOrEmpty(pattern) || buffer.Length < pattern.Length)
                return false;

            int limit = Math.Min(buffer.Length, 1024);
            if (limit < pattern.Length) return false;

            for (int i = 0; i <= limit - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    byte b = buffer[i + j];
                    char c1 = b >= 97 && b <= 122 ? (char)(b - 32) : (char)b;
                    char c2 = pattern[j];
                    if (c2 >= 'a' && c2 <= 'z') c2 = (char)(c2 - 32);

                    if (c1 != c2)
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        }

        #endregion
    }
}
