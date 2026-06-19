using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using SmartFileKit.Analysis;
using SmartFileKit.Domain;
using Xunit;

namespace SmartFileKit.Tests
{
    public class AnalysisTests
    {
        [Fact]
        public void Analyze_EmptyStream_ShouldReturnEmptyFileIssue()
        {
            using (var stream = new MemoryStream(Array.Empty<byte>()))
            {
                var report = FileAnalyzer.Analyze(stream, "empty.txt");

                Assert.False(report.IsSafe);
                Assert.True(report.IsSuspicious);
                Assert.Equal(10, report.RiskScore);
                Assert.Equal(FileRiskLevel.Safe, report.RiskLevel);
                Assert.Single(report.Issues);
                Assert.Equal(IssueType.EmptyFile, report.Issues[0].Type);
            }
        }

        [Fact]
        public void Analyze_SignatureMismatch_ExeRenamedToPdf_ShouldBeHighRisk()
        {
            byte[] buffer = new byte[100];
            buffer[0] = 0x4D;
            buffer[1] = 0x5A;

            using (var stream = new MemoryStream(buffer))
            {
                var report = FileAnalyzer.Analyze(stream, "invoice.pdf");

                Assert.False(report.IsSafe);
                Assert.True(report.IsSuspicious);
                Assert.True(report.RiskScore >= 90);
                Assert.Equal(FileRiskLevel.High, report.RiskLevel);
                Assert.Contains(report.Issues, i => i.Type == IssueType.SignatureMismatch);
            }
        }

        [Fact]
        public void Analyze_RawExecutableUpload_ShouldBeMediumRiskWithSuspiciousExtension()
        {
            byte[] buffer = new byte[100];
            buffer[0] = 0x4D;
            buffer[1] = 0x5A;

            using (var stream = new MemoryStream(buffer))
            {
                var report = FileAnalyzer.Analyze(stream, "danger.exe");

                Assert.False(report.IsSafe);
                Assert.True(report.IsSuspicious);
                Assert.Equal(70, report.RiskScore);
                Assert.Equal(FileRiskLevel.Medium, report.RiskLevel);
                Assert.Contains(report.Issues, i => i.Type == IssueType.SuspiciousExtension);
            }
        }

        [Fact]
        public void Analyze_MimeMismatch_ShouldBeDetected()
        {
            byte[] buffer = new byte[100];
            buffer[0] = 0x25; // %
            buffer[1] = 0x50; // P
            buffer[2] = 0x44; // D
            buffer[3] = 0x46; // F

            using (var stream = new MemoryStream(buffer))
            {
                var report = FileAnalyzer.Analyze(stream, "report.pdf", "image/jpeg");

                Assert.True(report.IsSuspicious);
                Assert.Contains(report.Issues, i => i.Type == IssueType.MimeMismatch);
            }
        }

        [Fact]
        public void Analyze_DocxStructureInZip_ShouldRefineToDocx()
        {
            using (var ms = new MemoryStream())
            {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    var entry = archive.CreateEntry("word/document.xml");
                    using (var writer = new StreamWriter(entry.Open()))
                    {
                        writer.Write("<xml>document content</xml>");
                    }
                }

                ms.Position = 0;

                var report = FileAnalyzer.Analyze(ms, "test.zip");

                Assert.Equal("docx", report.ActualFileType);
                Assert.Equal("application/vnd.openxmlformats-officedocument.wordprocessingml.document", report.DetectedMimeType);
            }
        }

        [Fact]
        public void Analyze_XlsxStructureInZip_ShouldRefineToXlsx()
        {
            using (var ms = new MemoryStream())
            {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    var entry = archive.CreateEntry("xl/workbook.xml");
                    using (var writer = new StreamWriter(entry.Open()))
                    {
                        writer.Write("<xml>workbook content</xml>");
                    }
                }

                ms.Position = 0;

                var report = FileAnalyzer.Analyze(ms, "report.xlsx");

                Assert.Equal("xlsx", report.ActualFileType);
                Assert.Equal("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", report.DetectedMimeType);
                Assert.True(report.IsSafe);
            }
        }

        [Fact]
        public void Analyze_ZipContainingExecutable_ShouldFlagExecutableContent()
        {
            using (var ms = new MemoryStream())
            {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    var entry = archive.CreateEntry("malware.exe");
                    using (var writer = new StreamWriter(entry.Open()))
                    {
                        writer.Write("some fake executable code");
                    }
                }

                ms.Position = 0;

                var report = FileAnalyzer.Analyze(ms, "files.zip");

                Assert.False(report.IsSafe);
                Assert.True(report.IsSuspicious);
                Assert.Equal(85, report.RiskScore);
                Assert.Equal(FileRiskLevel.High, report.RiskLevel);
                Assert.Contains(report.Issues, i => i.Type == IssueType.ExecutableContentDetected);
            }
        }

        [Fact]
        public void Analyze_PolyglotPdfExe_ShouldFlagMultipleSignature()
        {
            byte[] buffer = new byte[1024];
            buffer[0] = 0x25;
            buffer[1] = 0x50;
            buffer[2] = 0x44;
            buffer[3] = 0x46;

            int mzOffset = 100;
            buffer[mzOffset] = 0x4D;
            buffer[mzOffset + 1] = 0x5A;

            int peOffset = 16;
            buffer[mzOffset + 0x3C] = (byte)peOffset;
            buffer[mzOffset + 0x3D] = 0;
            buffer[mzOffset + 0x3E] = 0;
            buffer[mzOffset + 0x3F] = 0;

            int peStart = mzOffset + peOffset;
            buffer[peStart] = 0x50;
            buffer[peStart + 1] = 0x45;
            buffer[peStart + 2] = 0x00;
            buffer[peStart + 3] = 0x00;

            using (var stream = new MemoryStream(buffer))
            {
                var report = FileAnalyzer.Analyze(stream, "document.pdf");

                Assert.False(report.IsSafe);
                Assert.True(report.IsSuspicious);
                Assert.Equal(95, report.RiskScore);
                Assert.Contains(report.Issues, i => i.Type == IssueType.MultipleSignatureDetected);
            }
        }

        [Fact]
        public void EntropyCalculator_PlainTextVsRandomBytes()
        {
            byte[] textBytes = System.Text.Encoding.ASCII.GetBytes(new string('A', 1000));
            double textEntropy = EntropyCalculator.Calculate(textBytes, textBytes.Length);

            byte[] randomBytes = new byte[1000];
            new Random().NextBytes(randomBytes);
            double randomEntropy = EntropyCalculator.Calculate(randomBytes, randomBytes.Length);

            Assert.True(textEntropy < 1.0);
            Assert.True(randomEntropy > 7.0);
        }

        [Fact]
        public void Analyze_HighEntropyTextFile_ShouldFlagSuspicious()
        {
            byte[] randomBytes = new byte[2000];
            new Random().NextBytes(randomBytes);

            using (var stream = new MemoryStream(randomBytes))
            {
                var report = FileAnalyzer.Create()
                    .CheckEntropy(true, threshold: 7.2)
                    .Analyze(stream, "clean_text.txt");

                Assert.False(report.IsSafe);
                Assert.Contains(report.Issues, i => i.Type == IssueType.UnknownFileType && i.Description.Contains("high-entropy"));
            }
        }

        [Fact]
        public void FluentAPI_Configuration_ShouldRespectOptions()
        {
            byte[] buffer = new byte[100];
            buffer[0] = 0x50;
            buffer[1] = 0x4B;
            buffer[2] = 0x03;
            buffer[3] = 0x04;

            using (var stream = new MemoryStream(buffer))
            {
                var report = FileAnalyzer.Create()
                    .ValidateSignature(false)
                    .ValidateStructure(false)
                    .CalculateRiskScore(false)
                    .Analyze(stream, "invoice.pdf");

                Assert.True(report.IsSafe);
                Assert.Empty(report.Issues);
                Assert.Equal(0, report.RiskScore);
            }
        }
    }
}
