using System;
using System.Collections.Generic;
using System.IO;
using SmartFileKit.Analysis.Archives;
using SmartFileKit.Detection;
using SmartFileKit.Domain;

namespace SmartFileKit.Analysis
{
    /// <summary>
    /// Core engine for analyzing uploaded files, validating signatures, detecting spoofing, and assessing security risks.
    /// </summary>
    public class FileAnalyzer
    {
        private readonly FileAnalysisOptions _options;
        private readonly ZipArchiveInspector _zipInspector = new ZipArchiveInspector();

        /// <summary>
        /// Initializes a new instance of the <see cref="FileAnalyzer"/> class with specified options.
        /// </summary>
        public FileAnalyzer(FileAnalysisOptions options)
        {
            _options = options ?? new FileAnalysisOptions();
        }

        /// <summary>
        /// Starts the fluent builder pipeline.
        /// </summary>
        public static FileAnalyzerBuilder Create() => new FileAnalyzerBuilder();

        /// <summary>
        /// Analyzes a file stream using default options.
        /// </summary>
        public static FileAnalysisReport Analyze(Stream stream, string fileName = null, string contentType = null)
        {
            return new FileAnalyzer(new FileAnalysisOptions()).AnalyzeInternal(stream, fileName, contentType);
        }

        /// <summary>
        /// Internal implementation of the analysis workflow.
        /// </summary>
        internal FileAnalysisReport AnalyzeInternal(Stream stream, string fileName, string contentType)
        {
            var issues = new List<FileIssue>();

            if (stream == null)
            {
                issues.Add(new FileIssue(IssueType.CorruptedFile, "File stream is null.", FileRiskLevel.Medium));
                return new FileAnalysisReport(
                    actualFileType: "unknown",
                    detectedMimeType: "application/octet-stream",
                    riskScore: 45,
                    riskLevel: FileRiskLevel.Medium,
                    issues: issues.AsReadOnly());
            }

            long streamLength = 0;
            try
            {
                streamLength = stream.Length;
            }
            catch
            {
                // Non-seekable stream length is not readable, assume standard flow
            }

            if (streamLength == 0 && stream.CanSeek)
            {
                issues.Add(new FileIssue(IssueType.EmptyFile, "The file is empty (0 bytes).", FileRiskLevel.Low));
                return new FileAnalysisReport(
                    actualFileType: "unknown",
                    detectedMimeType: "application/octet-stream",
                    riskScore: 10,
                    riskLevel: FileRiskLevel.Safe,
                    issues: issues.AsReadOnly());
            }

            // 1. Read buffer (first 4096 bytes)
            long originalPosition = 0;
            bool canSeek = stream.CanSeek;
            if (canSeek)
            {
                originalPosition = stream.Position;
            }

            byte[] buffer = new byte[4096];
            int totalBytesRead = 0;
            try
            {
                int bytesRead;
                while (totalBytesRead < buffer.Length &&
                       (bytesRead = stream.Read(buffer, totalBytesRead, buffer.Length - totalBytesRead)) > 0)
                {
                    totalBytesRead += bytesRead;
                }
            }
            catch (Exception ex)
            {
                issues.Add(new FileIssue(IssueType.CorruptedFile, $"Failed to read file header: {ex.Message}", FileRiskLevel.Medium));
                return new FileAnalysisReport(
                    actualFileType: "unknown",
                    detectedMimeType: "application/octet-stream",
                    riskScore: 45,
                    riskLevel: FileRiskLevel.Medium,
                    issues: issues.AsReadOnly());
            }
            finally
            {
                if (canSeek)
                {
                    try { stream.Position = originalPosition; } catch { }
                }
            }

            // Trim buffer
            byte[] activeBuffer = buffer;
            if (totalBytesRead < buffer.Length)
            {
                activeBuffer = new byte[totalBytesRead];
                Array.Copy(buffer, activeBuffer, totalBytesRead);
            }

            // 2. Signature Detection
            FileFormatInfo detectedFormat = null;
            if (_options.ValidateSignature && activeBuffer.Length > 0)
            {
                detectedFormat = FormatDetector.Detect(activeBuffer);
            }

            // Extract file extension from name
            string fileExt = string.Empty;
            if (!string.IsNullOrEmpty(fileName))
            {
                try
                {
                    fileExt = Path.GetExtension(fileName).Trim().ToLowerInvariant();
                }
                catch
                {
                    // Ignore malformed path errors
                }
            }

            // Get expected format details based on extension
            FileFormatInfo expectedFormat = null;
            if (!string.IsNullOrEmpty(fileExt))
            {
                expectedFormat = FindFormatByExtension(fileExt);
            }

            // 3. Mismatch / Spoofing Analysis
            if (_options.ValidateSignature)
            {
                if (detectedFormat != null)
                {
                    if (expectedFormat != null)
                    {
                        // Check if detected signature category/extension matches expectations
                        if (!detectedFormat.Extension.Equals(expectedFormat.Extension, StringComparison.OrdinalIgnoreCase))
                        {
                            // Special case: Office formats vs ZIP
                            bool isOfficeZipMismatch = (expectedFormat.Extension == ".docx" || expectedFormat.Extension == ".xlsx" || expectedFormat.Extension == ".pptx") &&
                                                       detectedFormat.Extension == ".zip";

                            if (!isOfficeZipMismatch)
                            {
                                issues.Add(new FileIssue(
                                    IssueType.SignatureMismatch,
                                    $"File signature mismatch (Spoofing). File extension suggests '{fileExt}' ({expectedFormat.Category}), but actual content matches '{detectedFormat.Extension}' ({detectedFormat.Category}).",
                                    FileRiskLevel.High));
                            }
                        }
                    }
                    else if (!string.IsNullOrEmpty(fileExt))
                    {
                        // Recognized signature but unrecognized extension
                        issues.Add(new FileIssue(
                            IssueType.SignatureMismatch,
                            $"File signature mismatch (Spoofing). Extension '{fileExt}' is unrecognized, but actual content matches '{detectedFormat.Extension}' ({detectedFormat.Category}).",
                            FileRiskLevel.High));
                    }
                }
                else if (expectedFormat != null && expectedFormat.Signatures.Count > 0)
                {
                    // Expected format has signature, but none matched
                    issues.Add(new FileIssue(
                        IssueType.InvalidHeader,
                        $"File lacks a valid header signature for the expected format '{fileExt}'.",
                        FileRiskLevel.Medium));
                }
                else if (expectedFormat == null && !string.IsNullOrEmpty(fileExt))
                {
                    // No signature matched and unrecognized extension
                    issues.Add(new FileIssue(
                        IssueType.UnknownFileType,
                        $"Unknown file format and extension '{fileExt}'.",
                        FileRiskLevel.Low));
                }
            }

            // 4. MIME validation
            if (_options.ValidateMime && !string.IsNullOrEmpty(contentType))
            {
                string cleanClientMime = contentType.Trim().ToLowerInvariant();
                string expectedMime = expectedFormat?.MimeType ?? MimeMapper.GetMimeType(fileExt);

                // Check if client MIME differs from extension MIME
                if (!string.IsNullOrEmpty(expectedMime) && !cleanClientMime.Equals(expectedMime, StringComparison.OrdinalIgnoreCase))
                {
                    // Common browser generic MIME types can be ignored (e.g. application/octet-stream)
                    if (cleanClientMime != "application/octet-stream" && cleanClientMime != "application/x-generic")
                    {
                        issues.Add(new FileIssue(
                            IssueType.MimeMismatch,
                            $"MIME type mismatch. Client suggests '{cleanClientMime}', but file extension '{fileExt}' suggests '{expectedMime}'.",
                            FileRiskLevel.Low));
                    }
                }
            }

            // 5. Structure validation (ZIP / Office formats)
            string actualFileType = detectedFormat?.Extension?.TrimStart('.') ?? (expectedFormat?.Extension?.TrimStart('.') ?? string.Empty);
            string detectedMime = detectedFormat?.MimeType ?? (expectedFormat?.MimeType ?? "application/octet-stream");
            FileCategory activeCategory = detectedFormat?.Category ?? (expectedFormat?.Category ?? FileCategory.Unknown);

            if (_options.ValidateStructure)
            {
                bool isZipFormat = detectedFormat?.Extension == ".zip" || detectedFormat?.Extension == ".docx" || detectedFormat?.Extension == ".xlsx" || detectedFormat?.Extension == ".pptx" || fileExt == ".zip" || fileExt == ".docx" || fileExt == ".xlsx" || fileExt == ".pptx";
                if (isZipFormat && activeBuffer.Length > 0)
                {
                    var zipResult = _zipInspector.Inspect(stream);
                    if (zipResult.IsCorrupted)
                    {
                        issues.Add(new FileIssue(
                            IssueType.CorruptedFile,
                            "The zip archive structure appears to be corrupted or cannot be parsed.",
                            FileRiskLevel.Medium));
                    }
                    else
                    {
                        if (zipResult.ContainsExecutable)
                        {
                            issues.Add(new FileIssue(
                                IssueType.ExecutableContentDetected,
                                "The archive contains executable entries (e.g. .exe, .dll, .bat).",
                                FileRiskLevel.High));
                        }

                        if (zipResult.ContainsMacros)
                        {
                            issues.Add(new FileIssue(
                                IssueType.ExecutableContentDetected,
                                "The Office document contains macro project binaries (VBA macros).",
                                FileRiskLevel.High));
                        }

                        // Refine modern Office formats based on zip internal directory
                        if (!string.IsNullOrEmpty(zipResult.DetectedOfficeFormat))
                        {
                            actualFileType = zipResult.DetectedOfficeFormat;
                            detectedMime = MimeMapper.GetMimeType(actualFileType);
                            activeCategory = MimeMapper.GetCategory(actualFileType);

                            // Verify if it matched the expected format
                            if (!string.IsNullOrEmpty(fileExt) && !fileExt.Equals("." + actualFileType, StringComparison.OrdinalIgnoreCase))
                            {
                                issues.Add(new FileIssue(
                                    IssueType.SignatureMismatch,
                                    $"File signature mismatch (Spoofing). Extension suggests '{fileExt}', but content structure is '{actualFileType}'.",
                                    FileRiskLevel.High));
                            }
                        }
                    }
                }
            }

            // 6. Suspicious extension check (raw executables / scripts uploaded directly)
            if (activeCategory == FileCategory.Executable || actualFileType == "exe" || actualFileType == "dll" || actualFileType == "msi" || actualFileType == "sys" || actualFileType == "bat" || actualFileType == "sh")
            {
                issues.Add(new FileIssue(
                    IssueType.SuspiciousExtension,
                    $"The file is an executable or system binary ('{actualFileType}'), which presents higher security risks.",
                    FileRiskLevel.Medium));
            }

            // 7. Polyglot detection
            if (_options.ValidateSignature && activeBuffer.Length > 0)
            {
                if (PolyglotDetector.Detect(activeBuffer, detectedFormat))
                {
                    issues.Add(new FileIssue(
                        IssueType.MultipleSignatureDetected,
                        "Multiple file signatures detected (Polyglot file structure).",
                        FileRiskLevel.High));
                }
            }

            // 8. Entropy calculation
            double? finalEntropy = null;
            if (_options.CheckEntropy)
            {
                long bytesAnalyzed;
                double entropy = EntropyCalculator.Calculate(stream, out bytesAnalyzed, _options.MaxBytesForEntropy);
                finalEntropy = entropy;

                // High entropy on text files is highly suspicious (obfuscated data)
                bool isTextLike = actualFileType == "txt" || actualFileType == "csv" || actualFileType == "json" || actualFileType == "xml" || actualFileType == "html";
                if (isTextLike && entropy > _options.EntropyThreshold)
                {
                    issues.Add(new FileIssue(
                        IssueType.UnknownFileType,
                        $"Suspicious high-entropy content ({entropy:F2}) found in plain text format '{actualFileType}', indicating possible obfuscated payload.",
                        FileRiskLevel.Medium));
                }
            }

            // 9. Risk score and level
            int riskScore = 0;
            if (_options.CalculateRiskScore)
            {
                riskScore = CalculateRisk(issues, actualFileType, activeCategory);
            }
            var riskLevel = GetRiskLevel(riskScore);

            return new FileAnalysisReport(
                actualFileType: actualFileType,
                detectedMimeType: detectedMime,
                riskScore: riskScore,
                riskLevel: riskLevel,
                issues: issues.AsReadOnly(),
                entropy: finalEntropy);
        }

        private FileFormatInfo FindFormatByExtension(string ext)
        {
            if (string.IsNullOrEmpty(ext)) return null;
            string clean = ext.Trim();
            if (!clean.StartsWith(".", StringComparison.Ordinal)) clean = "." + clean;
            clean = clean.ToLowerInvariant();

            foreach (var format in FileFormatRegistry.Formats)
            {
                if (format.Extension.Equals(clean, StringComparison.OrdinalIgnoreCase))
                    return format;
            }
            return null;
        }

        private int CalculateRisk(List<FileIssue> issues, string actualFileType, FileCategory category)
        {
            if (issues.Count == 0)
            {
                if (category == FileCategory.Executable || actualFileType == "exe" || actualFileType == "dll" || actualFileType == "msi" || actualFileType == "sys")
                {
                    return 70; // High default risk for executables
                }
                return 0;
            }

            int maxScore = 0;
            foreach (var issue in issues)
            {
                int score = GetIssueRiskWeight(issue.Type);
                if (score > maxScore)
                {
                    maxScore = score;
                }
            }

            // Hybrid calculation: max score plus 5 points for every additional issue
            int finalScore = maxScore + (issues.Count - 1) * 5;

            // Apply base risk for executables
            if (category == FileCategory.Executable || actualFileType == "exe" || actualFileType == "dll" || actualFileType == "msi" || actualFileType == "sys")
            {
                if (finalScore < 70) finalScore = 70;
            }

            return Math.Min(100, finalScore);
        }

        private int GetIssueRiskWeight(IssueType type)
        {
            switch (type)
            {
                case IssueType.MultipleSignatureDetected:
                    return 95;
                case IssueType.SignatureMismatch:
                    return 90;
                case IssueType.ExecutableContentDetected:
                    return 85;
                case IssueType.SuspiciousExtension:
                    return 60;
                case IssueType.CorruptedFile:
                    return 45;
                case IssueType.InvalidHeader:
                    return 40;
                case IssueType.MimeMismatch:
                    return 30;
                case IssueType.UnknownFileType:
                    return 25;
                case IssueType.EmptyFile:
                    return 10;
                default:
                    return 0;
            }
        }

        private FileRiskLevel GetRiskLevel(int score)
        {
            if (score <= 20) return FileRiskLevel.Safe;
            if (score <= 50) return FileRiskLevel.Low;
            if (score <= 80) return FileRiskLevel.Medium;
            return FileRiskLevel.High;
        }
    }
}
