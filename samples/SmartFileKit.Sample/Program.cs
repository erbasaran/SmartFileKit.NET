using SmartFileKit.Domain;
using SmartFileKit.Validation;
using SmartFileKit.Analysis;
using SmartFileKit.Security;
using SmartFileKit.Detection;
using System;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace SmartFileKit.Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("==================================================");
            Console.WriteLine("          SmartFileKit Demonstration              ");
            Console.WriteLine("==================================================");
            Console.WriteLine();

            DemoFileSize();
            DemoSanitizer();
            DemoDetection();
            DemoValidation();
            DemoAnalyzer();
            DemoSecurityAndMetadata();

            Console.WriteLine();
            Console.WriteLine("==================================================");
            Console.WriteLine("        Demonstration Complete Successfully       ");
            Console.WriteLine("==================================================");
        }

        static void DemoFileSize()
        {
            Console.WriteLine("--- 1. File Size Formatting ---");
            long bytes = 1048576 * 5; // 5 MB
            FileSize size = bytes.ToFileSize();
            Console.WriteLine($"Conversions for {bytes} bytes:");
            Console.WriteLine($"* Megabytes: {size.Megabytes} MB");
            Console.WriteLine($"* ToString(): {size.ToString()}");
            Console.WriteLine($"* ToString(1): {size.ToString(1)}");

            FileSize fluentSize = 250.MB();
            Console.WriteLine($"Fluent size 250.MB(): {fluentSize}");
            Console.WriteLine($"Addition (5MB + 250MB): {size + fluentSize}");
            Console.WriteLine();
        }

        static void DemoSanitizer()
        {
            Console.WriteLine("--- 2. File Name Sanitization ---");
            string dirtyName1 = "özel dosya (1).png";
            string sanitized1 = FileName.Sanitize(dirtyName1);
            Console.WriteLine($"Original:  \"{dirtyName1}\"");
            Console.WriteLine($"Sanitized: \"{sanitized1}\"");
            Console.WriteLine();

            string traversalName = "../../etc/passwd";
            string sanitizedTraversal = FileName.Sanitize(traversalName);
            Console.WriteLine($"Original (Path Traversal): \"{traversalName}\"");
            Console.WriteLine($"Sanitized:                \"{sanitizedTraversal}\"");
            Console.WriteLine();

            string reservedName = "CON.txt";
            string sanitizedReserved = FileName.Sanitize(reservedName);
            Console.WriteLine($"Original (Windows Reserved): \"{reservedName}\"");
            Console.WriteLine($"Sanitized:                  \"{sanitizedReserved}\"");
            Console.WriteLine();
        }

        static void DemoDetection()
        {
            Console.WriteLine("--- 3. File MIME & Category Detection ---");

            // PNG Bytes
            byte[] pngBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
            var pngFormat = FileType.GetFormat(pngBytes);
            Console.WriteLine("PNG detection from byte array:");
            Console.WriteLine($"* Primary Extension: {pngFormat?.Extension}");
            Console.WriteLine($"* MIME Type:         {pngFormat?.MimeType}");
            Console.WriteLine($"* Category:          {pngFormat?.Category}");
            Console.WriteLine();

            // Word Docx Bytes (ZIP signature + word/)
            byte[] docxBytes = new byte[100];
            docxBytes[0] = 0x50; docxBytes[1] = 0x4B; docxBytes[2] = 0x03; docxBytes[3] = 0x04;
            byte[] wordPattern = Encoding.ASCII.GetBytes("word/");
            Buffer.BlockCopy(wordPattern, 0, docxBytes, 20, wordPattern.Length);

            var docxFormat = FileType.GetFormat(docxBytes);
            Console.WriteLine("Office Word (.docx) detection from byte array:");
            Console.WriteLine($"* Extension:         {docxFormat?.Extension}");
            Console.WriteLine($"* MIME Type:         {docxFormat?.MimeType}");
            Console.WriteLine($"* Category:          {docxFormat?.Category}");
            Console.WriteLine();
        }

        static void DemoValidation()
        {
            Console.WriteLine("--- 4. Fluent File Validation ---");

            // Case A: Valid PNG upload
            Console.WriteLine("Case A: Valid PNG upload:");
            byte[] validPng = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
            var resultA = FileValidator.Validate(validPng, "my_avatar.png")
                .MaxSize(2.MB())
                .AllowedExtensions(".png", ".jpg")
                .AllowedCategories(FileCategory.Image)
                .Execute();
            Console.WriteLine($"* Is Valid? {resultA.IsValid}");
            foreach (var err in resultA.Errors)
            {
                Console.WriteLine($"  Error: {err}");
            }
            Console.WriteLine();

            // Case B: Spoofed File (virus.exe renamed to holiday.jpg)
            Console.WriteLine("Case B: Spoofed Upload (virus.exe renamed to holiday.jpg):");
            byte[] spoofedBytes = Encoding.ASCII.GetBytes("MZ\x90\x00\x03\x00\x00\x00...");
            var resultB = FileValidator.Validate(spoofedBytes, "holiday.jpg")
                .MaxSize(5.MB())
                .AllowedExtensions(".jpg", ".jpeg")
                .AllowedCategories(FileCategory.Image)
                .Execute();
            Console.WriteLine($"* Is Valid? {resultB.IsValid}");
            foreach (var err in resultB.Errors)
            {
                Console.WriteLine($"  Error: {err}");
            }
            Console.WriteLine();

            // Case C: ThrowIfInvalid usage
            Console.WriteLine("Case C: Exception throwing with ThrowIfInvalid():");
            try
            {
                FileValidator.Validate(spoofedBytes, "malicious.png")
                    .AllowedCategories(FileCategory.Image)
                    .ThrowIfInvalid();
            }
            catch (FileValidationException ex)
            {
                Console.WriteLine("Caught Expected Exception:");
                Console.WriteLine(ex.Message);
            }
            Console.WriteLine();
        }

        static void DemoAnalyzer()
        {
            Console.WriteLine("--- 5. Advanced File Analysis & Security Engine ---");
            Console.WriteLine();

            // Case A: Spoofed File (EXE disguised as PDF)
            byte[] spoofedBytes = new byte[100];
            spoofedBytes[0] = 0x4D; spoofedBytes[1] = 0x5A; // MZ header
            using (var stream = new MemoryStream(spoofedBytes))
            {
                var report = FileAnalyzer.Analyze(stream, "annual_report.pdf");
                Console.WriteLine("Case A: Spoofed File (MZ Executable renamed to annual_report.pdf):");
                Console.WriteLine($"* Is Safe?       {report.IsSafe}");
                Console.WriteLine($"* Is Suspicious? {report.IsSuspicious}");
                Console.WriteLine($"* Risk Score:    {report.RiskScore} / 100 ({report.RiskLevel})");
                Console.WriteLine($"* Actual Type:   {report.ActualFileType}");
                foreach (var issue in report.Issues)
                {
                    Console.WriteLine($"  - [{issue.Severity}] {issue.Type}: {issue.Description}");
                }
                Console.WriteLine();
            }

            // Case B: ZIP Archive containing a hidden Executable
            using (var ms = new MemoryStream())
            {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    var entry = archive.CreateEntry("dangerous_payload.exe");
                    using (var writer = new StreamWriter(entry.Open()))
                    {
                        writer.Write("MZ..."); // dummy exe
                    }
                }
                ms.Position = 0;

                var report = FileAnalyzer.Analyze(ms, "documents.zip");
                Console.WriteLine("Case B: ZIP Archive containing inner executable:");
                Console.WriteLine($"* Is Safe?       {report.IsSafe}");
                Console.WriteLine($"* Risk Score:    {report.RiskScore} / 100 ({report.RiskLevel})");
                foreach (var issue in report.Issues)
                {
                    Console.WriteLine($"  - [{issue.Severity}] {issue.Type}: {issue.Description}");
                }
                Console.WriteLine();
            }

            // Case C: Polyglot File Detection (PDF carrying nested MZ PE executable)
            byte[] polyglotBytes = new byte[1024];
            polyglotBytes[0] = 0x25; polyglotBytes[1] = 0x50; polyglotBytes[2] = 0x44; polyglotBytes[3] = 0x46; // %PDF
            int mzOffset = 100;
            polyglotBytes[mzOffset] = 0x4D; polyglotBytes[mzOffset + 1] = 0x5A; // MZ
            int peOffset = 16;
            polyglotBytes[mzOffset + 0x3C] = (byte)peOffset; // PE Offset
            int peStart = mzOffset + peOffset;
            polyglotBytes[peStart] = 0x50; polyglotBytes[peStart + 1] = 0x45; // PE\x00\x00
            
            using (var stream = new MemoryStream(polyglotBytes))
            {
                var report = FileAnalyzer.Analyze(stream, "legit.pdf");
                Console.WriteLine("Case C: Polyglot File (PDF embedding MZ/PE Executable):");
                Console.WriteLine($"* Is Safe?       {report.IsSafe}");
                Console.WriteLine($"* Is Suspicious? {report.IsSuspicious}");
                Console.WriteLine($"* Risk Score:    {report.RiskScore} / 100");
                foreach (var issue in report.Issues)
                {
                    Console.WriteLine($"  - [{issue.Severity}] {issue.Type}: {issue.Description}");
                }
                Console.WriteLine();
            }

            // Case D: Entropy Analysis & Builder API
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(new string('A', 2000));
            byte[] highEntropyBytes = new byte[2000];
            new Random().NextBytes(highEntropyBytes);

            using (var plainStream = new MemoryStream(plainTextBytes))
            using (var highStream = new MemoryStream(highEntropyBytes))
            {
                var plainReport = FileAnalyzer.Create().CheckEntropy(true).Analyze(plainStream, "regular.txt");
                var highReport = FileAnalyzer.Create().CheckEntropy(true, threshold: 7.0).Analyze(highStream, "hidden.txt");

                Console.WriteLine("Case D: Entropy Analysis & Builder API:");
                Console.WriteLine($"* Regular text entropy: {plainReport.Entropy:F2} (Is Suspicious: {plainReport.IsSuspicious})");
                Console.WriteLine($"* Obfuscated text entropy: {highReport.Entropy:F2} (Is Suspicious: {highReport.IsSuspicious})");
                if (highReport.IsSuspicious)
                {
                    foreach (var issue in highReport.Issues)
                    {
                        Console.WriteLine($"  - [{issue.Severity}] {issue.Type}: {issue.Description}");
                    }
                }
                Console.WriteLine();
            }
        }

        static void DemoSecurityAndMetadata()
        {
            Console.WriteLine("--- 6. Cryptographic Hashing & Duplicate Detection ---");
            byte[] fileContent = Encoding.UTF8.GetBytes("SmartFileKit Security Engine Demonstration Content");
            using (var s1 = new MemoryStream(fileContent))
            using (var s2 = new MemoryStream(fileContent))
            {
                string sha256 = FileHash.Sha256(s1);
                string md5 = FileHash.Calculate(s1, HashAlgorithmType.MD5);
                bool matches = DuplicateDetector.AreSame(s1, s2);

                Console.WriteLine($"* SHA-256 Hash: {sha256}");
                Console.WriteLine($"* MD5 Hash:     {md5}");
                Console.WriteLine($"* Duplicate check AreSame(): {matches}");
                Console.WriteLine();
            }

            Console.WriteLine("--- 7. File Name Risk & Security Analysis ---");
            string filenameA = "invoice.pdf.exe";
            var doubleExtResult = FileSecurity.HasDoubleExtension(filenameA);
            Console.WriteLine($"Filename: \"{filenameA}\"");
            Console.WriteLine($"* Has Double Extension? {doubleExtResult.HasDoubleExtension}");
            Console.WriteLine($"* Primary: {doubleExtResult.PrimaryExtension}, Secondary: {doubleExtResult.SecondExtension}");
            Console.WriteLine($"* Is Second Extension Dangerous? {doubleExtResult.IsDangerous}");

            string filenameB = "../../../CON.txt";
            var pathRisk = FileSecurity.AnalyzeFileName(filenameB);
            Console.WriteLine($"Filename: \"{filenameB}\"");
            Console.WriteLine($"* Risk Score: {pathRisk.RiskScore} / 100");
            foreach (var issue in pathRisk.Issues)
            {
                Console.WriteLine($"  - {issue}");
            }
            Console.WriteLine();

            Console.WriteLine("--- 8. Image & Office Metadata Readers ---");
            // Mock PNG image
            byte[] mockPng = new byte[30];
            mockPng[0] = 0x89; mockPng[1] = 0x50; mockPng[2] = 0x4E; mockPng[3] = 0x47;
            mockPng[4] = 0x0D; mockPng[5] = 0x0A; mockPng[6] = 0x1A; mockPng[7] = 0x0A;
            mockPng[12] = 0x49; mockPng[13] = 0x48; mockPng[14] = 0x44; mockPng[15] = 0x52; // IHDR
            // Width 1280 (0x0500), Height 720 (0x02D0)
            mockPng[16] = 0x00; mockPng[17] = 0x00; mockPng[18] = 0x05; mockPng[19] = 0x00; // width 1280
            mockPng[20] = 0x00; mockPng[21] = 0x00; mockPng[22] = 0x02; mockPng[23] = 0xD0; // height 720
            
            using (var stream = new MemoryStream(mockPng))
            {
                var meta = ImageMetadata.Read(stream);
                if (meta.IsValid)
                {
                    Console.WriteLine($"Image Metadata: Format={meta.Format}, Resolution={meta.Width}x{meta.Height}");
                }
            }

            Console.WriteLine();
            Console.WriteLine("--- 9. File Signature Database Registry ---");
            var databaseJson = FileSignatureDatabase.ExportJson();
            Console.WriteLine($"* JSON Database Registry (Snippet):\n{databaseJson.Substring(0, Math.Min(250, databaseJson.Length))}...");
            Console.WriteLine();
        }
    }
}
