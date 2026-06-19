using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using SmartFileKit.Domain;
using SmartFileKit.Security;
using SmartFileKit.Detection;
using Xunit;

namespace SmartFileKit.Tests
{
    public class SecurityExtensionsTests
    {
        [Fact]
        public void FileHash_Calculate_ShouldMatchStandardCryptoOutput()
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes("SmartFileKit Security Engine Testing!");
            using (var stream = new MemoryStream(data))
            {
                string md5 = FileHash.Calculate(stream, HashAlgorithmType.MD5);
                string sha1 = FileHash.Calculate(stream, HashAlgorithmType.SHA1);
                string sha256 = FileHash.Calculate(stream, HashAlgorithmType.SHA256);
                string sha512 = FileHash.Calculate(stream, HashAlgorithmType.SHA512);

                // Compute standard
                using (var sha = SHA256.Create())
                {
                    string standardSha256 = BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
                    Assert.Equal(standardSha256, sha256);
                }

                Assert.Equal(32, md5.Length);
                Assert.Equal(40, sha1.Length);
                Assert.Equal(64, sha256.Length);
                Assert.Equal(128, sha512.Length);
                Assert.Equal(sha256, FileHash.Sha256(stream));
            }
        }

        [Fact]
        public void DuplicateDetector_AreSame_Streams_ShouldCompareBytesCorrectly()
        {
            byte[] data1 = { 1, 2, 3, 4, 5 };
            byte[] data2 = { 1, 2, 3, 4, 5 };
            byte[] data3 = { 1, 2, 3, 4, 6 };
            byte[] data4 = { 1, 2, 3, 4 };

            using (var s1 = new MemoryStream(data1))
            using (var s2 = new MemoryStream(data2))
            using (var s3 = new MemoryStream(data3))
            using (var s4 = new MemoryStream(data4))
            {
                Assert.True(DuplicateDetector.AreSame(s1, s2));
                Assert.False(DuplicateDetector.AreSame(s1, s3));
                Assert.False(DuplicateDetector.AreSame(s1, s4));
            }
        }

        [Fact]
        public void DuplicateDetector_Compare_HashesAndFingerprints_ShouldEvaluateCorrectly()
        {
            var fp1 = new FileFingerprint(100, "abc", "application/pdf", "pdf", FileCategory.Document);
            var fp2 = new FileFingerprint(100, "abc", "application/pdf", "pdf", FileCategory.Document);
            var fp3 = new FileFingerprint(200, "abc", "application/pdf", "pdf", FileCategory.Document);
            var fp4 = new FileFingerprint(100, "xyz", "application/pdf", "pdf", FileCategory.Document);

            Assert.True(DuplicateDetector.Compare("sha-hash", "sha-hash"));
            Assert.False(DuplicateDetector.Compare("sha-hash1", "sha-hash2"));

            Assert.True(DuplicateDetector.AreSame(fp1, fp2));
            Assert.False(DuplicateDetector.AreSame(fp1, fp3));
            Assert.False(DuplicateDetector.AreSame(fp1, fp4));
        }

        [Fact]
        public void FileFingerprint_Generate_ShouldPopulateDetails()
        {
            byte[] pdfBytes = new byte[100];
            pdfBytes[0] = 0x25; pdfBytes[1] = 0x50; pdfBytes[2] = 0x44; pdfBytes[3] = 0x46; // %PDF

            using (var stream = new MemoryStream(pdfBytes))
            {
                var fp = FileFingerprint.Generate(stream, "test.pdf");

                Assert.Equal(100, fp.Size);
                Assert.Equal("pdf", fp.SignatureType);
                Assert.Equal("application/pdf", fp.MimeType);
                Assert.Equal(FileCategory.Document, fp.Category);
                Assert.NotEmpty(fp.Sha256);
            }
        }

        [Fact]
        public void UploadPolicy_Validate_ShouldRespectRules()
        {
            byte[] exeBytes = new byte[100];
            exeBytes[0] = 0x4D; exeBytes[1] = 0x5A; // MZ

            var policy = UploadPolicy.Create()
                .AllowImages()
                .MaxSize(5.MB());

            using (var stream = new MemoryStream(exeBytes))
            {
                // Validate naming and format mismatch
                var result = policy.Validate(stream, "photo.jpg");
                Assert.False(result.IsValid);
                Assert.Contains(result.Errors, err => err.Contains("mismatch") || err.Contains("not allowed"));
            }
        }

        [Fact]
        public void FileSecurity_IsDangerousExtension_ShouldIdentifyDanger()
        {
            Assert.True(FileSecurity.IsDangerousExtension("malware.exe"));
            Assert.True(FileSecurity.IsDangerousExtension("script.ps1"));
            Assert.True(FileSecurity.IsDangerousExtension("payload.vbs"));
            Assert.False(FileSecurity.IsDangerousExtension("report.pdf"));
            Assert.False(FileSecurity.IsDangerousExtension("image.jpeg"));
        }

        [Fact]
        public void FileSecurity_HasDoubleExtension_ShouldDetectDisguise()
        {
            var res1 = FileSecurity.HasDoubleExtension("invoice.pdf.exe");
            Assert.True(res1.HasDoubleExtension);
            Assert.Equal(".pdf", res1.PrimaryExtension);
            Assert.Equal(".exe", res1.SecondExtension);
            Assert.True(res1.IsDangerous);

            var res2 = FileSecurity.HasDoubleExtension("v1.0.txt");
            Assert.False(res2.HasDoubleExtension); // .0 is not a letter-based valid extension

            var res3 = FileSecurity.HasDoubleExtension("normal_file.docx");
            Assert.False(res3.HasDoubleExtension);
        }

        [Fact]
        public void FileSecurity_AnalyzeFileName_ShouldFindRisks()
        {
            // Traversal
            var res1 = FileSecurity.AnalyzeFileName("../etc/passwd");
            Assert.True(res1.HasPathTraversal);
            Assert.False(res1.IsSafe);
            Assert.True(res1.RiskScore >= 80);

            // Traversal URL Encoded
            var res1Encoded = FileSecurity.AnalyzeFileName("%2e%2e%2fetc%2fpasswd");
            Assert.True(res1Encoded.HasPathTraversal);
            Assert.False(res1Encoded.IsSafe);

            // Reserved Name
            var res2 = FileSecurity.AnalyzeFileName("CON.txt");
            Assert.True(res2.IsReservedName);
            Assert.False(res2.IsSafe);

            // Shell Char
            var res3 = FileSecurity.AnalyzeFileName("file;rm.png");
            Assert.True(res3.HasSuspiciousCharacters);
            Assert.False(res3.IsSafe);

            // Safe Name
            var res4 = FileSecurity.AnalyzeFileName("safe_document_2026.docx");
            Assert.True(res4.IsSafe);
            Assert.Equal(0, res4.RiskScore);
        }

        [Fact]
        public void ImageMetadata_Read_ShouldParseSupportedFormats()
        {
            // 1. Mock PNG
            byte[] png = new byte[30];
            png[0] = 0x89; png[1] = 0x50; png[2] = 0x4E; png[3] = 0x47;
            png[4] = 0x0D; png[5] = 0x0A; png[6] = 0x1A; png[7] = 0x0A;
            png[12] = 0x49; png[13] = 0x48; png[14] = 0x44; png[15] = 0x52; // IHDR
            // Width: 100 (0x64), Height: 200 (0xC8)
            png[18] = 0x00; png[19] = 0x64;
            png[22] = 0x00; png[23] = 0xC8;

            using (var ms = new MemoryStream(png))
            {
                var meta = ImageMetadata.Read(ms);
                Assert.True(meta.IsValid);
                Assert.Equal(100, meta.Width);
                Assert.Equal(200, meta.Height);
                Assert.Equal("PNG", meta.Format);
            }

            // 2. Mock GIF
            byte[] gif = new byte[10];
            gif[0] = (byte)'G'; gif[1] = (byte)'I'; gif[2] = (byte)'F';
            gif[3] = (byte)'8'; gif[4] = (byte)'9'; gif[5] = (byte)'a';
            // Width: 150 (0x96), Height: 300 (0x012C)
            gif[6] = 0x96; gif[7] = 0x00;
            gif[8] = 0x2C; gif[9] = 0x01;

            using (var ms = new MemoryStream(gif))
            {
                var meta = ImageMetadata.Read(ms);
                Assert.True(meta.IsValid);
                Assert.Equal(150, meta.Width);
                Assert.Equal(300, meta.Height);
                Assert.Equal("GIF", meta.Format);
            }

            // 3. Mock BMP
            byte[] bmp = new byte[30];
            bmp[0] = 0x42; bmp[1] = 0x4D; // BM
            // Width: 80 (0x50), Height: 120 (0x78) at offsets 18 and 22
            bmp[18] = 0x50; bmp[19] = 0x00; bmp[20] = 0x00; bmp[21] = 0x00;
            bmp[22] = 0x78; bmp[23] = 0x00; bmp[24] = 0x00; bmp[25] = 0x00;

            using (var ms = new MemoryStream(bmp))
            {
                var meta = ImageMetadata.Read(ms);
                Assert.True(meta.IsValid);
                Assert.Equal(80, meta.Width);
                Assert.Equal(120, meta.Height);
                Assert.Equal("BMP", meta.Format);
            }
        }

        [Fact]
        public void OfficeMetadata_Read_ShouldParseOfficeProperties()
        {
            using (var ms = new MemoryStream())
            {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    // Core Props XML
                    var coreEntry = archive.CreateEntry("docProps/core.xml");
                    using (var writer = new StreamWriter(coreEntry.Open()))
                    {
                        writer.Write(@"<?xml version=""1.0"" encoding=""utf-8""?>
<cp:coreProperties xmlns:cp=""http://schemas.openxmlformats.org/package/2006/metadata/core-properties"" 
                    xmlns:dc=""http://purl.org/dc/elements/1.1/"" 
                    xmlns:dcterms=""http://purl.org/dc/terms/"">
  <dc:creator>Jane Doe</dc:creator>
  <dc:title>Strategic Proposal</dc:title>
  <dcterms:created>2026-06-19T12:00:00Z</dcterms:created>
  <dcterms:modified>2026-06-19T14:30:00Z</dcterms:modified>
</cp:coreProperties>");
                    }

                    // App Props XML
                    var appEntry = archive.CreateEntry("docProps/app.xml");
                    using (var writer = new StreamWriter(appEntry.Open()))
                    {
                        writer.Write(@"<?xml version=""1.0"" encoding=""utf-8""?>
<Properties xmlns=""http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"">
  <Company>Acme Corporation</Company>
</Properties>");
                    }
                }

                ms.Position = 0;
                var meta = OfficeMetadata.Read(ms);

                Assert.True(meta.IsValid);
                Assert.Equal("Jane Doe", meta.Author);
                Assert.Equal("Strategic Proposal", meta.Title);
                Assert.Equal("Acme Corporation", meta.Company);
                Assert.NotNull(meta.CreatedDate);
                Assert.NotNull(meta.ModifiedDate);
            }
        }

        [Fact]
        public void ArchiveInspector_ShouldDetectVbaMacros()
        {
            using (var ms = new MemoryStream())
            {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    archive.CreateEntry("word/vbaProject.bin");
                    archive.CreateEntry("word/document.xml");
                }

                ms.Position = 0;
                var result = new SmartFileKit.Analysis.Archives.ZipArchiveInspector().Inspect(ms);

                Assert.True(result.ContainsMacros);
                Assert.Equal("docx", result.DetectedOfficeFormat);
            }
        }

        [Fact]
        public void FileSignatureDatabase_GetAllAndExportJson_ShouldFunction()
        {
            var all = FileSignatureDatabase.GetAll();
            Assert.NotEmpty(all);

            string json = FileSignatureDatabase.ExportJson();
            Assert.NotEmpty(json);
            Assert.StartsWith("[", json);
            Assert.EndsWith("]", json.Trim());
            Assert.Contains("extension", json);
            Assert.Contains("mimeType", json);
            Assert.Contains("magicBytes", json);
        }

        [Fact]
        public void ImageMetadata_Read_ShouldParseNonSeekableStreamCorrectly()
        {
            byte[] png = new byte[30];
            png[0] = 0x89; png[1] = 0x50; png[2] = 0x4E; png[3] = 0x47;
            png[4] = 0x0D; png[5] = 0x0A; png[6] = 0x1A; png[7] = 0x0A;
            png[12] = 0x49; png[13] = 0x48; png[14] = 0x44; png[15] = 0x52; // IHDR
            // Width: 100, Height: 200
            png[18] = 0x00; png[19] = 0x64;
            png[22] = 0x00; png[23] = 0xC8;

            using (var ms = new MemoryStream(png))
            using (var nonSeekable = new NonSeekableStream(ms))
            {
                var meta = ImageMetadata.Read(nonSeekable);
                Assert.True(meta.IsValid);
                Assert.Equal(100, meta.Width);
                Assert.Equal(200, meta.Height);
                Assert.Equal("PNG", meta.Format);
            }
        }

        private class NonSeekableStream : Stream
        {
            private readonly Stream _inner;
            public NonSeekableStream(Stream inner) { _inner = inner; }
            public override bool CanRead => _inner.CanRead;
            public override bool CanSeek => false;
            public override bool CanWrite => _inner.CanWrite;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() => _inner.Flush();
            public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
        }
    }
}
