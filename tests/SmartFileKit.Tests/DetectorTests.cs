using SmartFileKit.Detection;
using SmartFileKit.Domain;
using System.Text;

namespace SmartFileKit.Tests
{
    public class DetectorTests
    {
        [Fact]
        public void Detect_Png_ShouldDetectCorrectly()
        {
            byte[] pngBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01 };
            var format = FormatDetector.Detect(pngBytes);
            Assert.NotNull(format);
            Assert.Equal(".png", format.Extension);
            Assert.Equal("image/png", format.MimeType);
            Assert.Equal(FileCategory.Image, format.Category);
        }

        [Fact]
        public void Detect_Jpeg_ShouldDetectCorrectly()
        {
            byte[] jpegBytes = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46 };
            var format = FormatDetector.Detect(jpegBytes);
            Assert.NotNull(format);
            Assert.Equal(".jpg", format.Extension);
            Assert.Equal("image/jpeg", format.MimeType);
        }

        [Fact]
        public void Detect_Pdf_ShouldDetectCorrectly()
        {
            byte[] pdfBytes = Encoding.ASCII.GetBytes("%PDF-1.4\n1 0 obj...");
            var format = FormatDetector.Detect(pdfBytes);
            Assert.NotNull(format);
            Assert.Equal(".pdf", format.Extension);
            Assert.Equal(FileCategory.Document, format.Category);
        }

        [Fact]
        public void Detect_Exe_ShouldDetectCorrectly()
        {
            byte[] exeBytes = Encoding.ASCII.GetBytes("MZ\x90\x00\x03\x00\x00\x00...");
            var format = FormatDetector.Detect(exeBytes);
            Assert.NotNull(format);
            Assert.Equal(".exe", format.Extension);
            Assert.Equal(FileCategory.Executable, format.Category);
        }

        [Fact]
        public void Detect_Docx_ShouldDetectCorrectly()
        {
            // ZIP signature + "word/" entry string
            byte[] docxBytes = new byte[100];
            docxBytes[0] = 0x50; docxBytes[1] = 0x4B; docxBytes[2] = 0x03; docxBytes[3] = 0x04;
            byte[] wordPattern = Encoding.ASCII.GetBytes("word/");
            System.Buffer.BlockCopy(wordPattern, 0, docxBytes, 20, wordPattern.Length);

            var format = FormatDetector.Detect(docxBytes);
            Assert.NotNull(format);
            Assert.Equal(".docx", format.Extension);
        }

        [Fact]
        public void Detect_Xlsx_ShouldDetectCorrectly()
        {
            // ZIP signature + "xl/" entry string
            byte[] xlsxBytes = new byte[100];
            xlsxBytes[0] = 0x50; xlsxBytes[1] = 0x4B; xlsxBytes[2] = 0x03; xlsxBytes[3] = 0x04;
            byte[] xlPattern = Encoding.ASCII.GetBytes("xl/");
            System.Buffer.BlockCopy(xlPattern, 0, xlsxBytes, 20, xlPattern.Length);

            var format = FormatDetector.Detect(xlsxBytes);
            Assert.NotNull(format);
            Assert.Equal(".xlsx", format.Extension);
        }

        [Fact]
        public void Detect_Zip_ShouldDetectCorrectly()
        {
            // ZIP signature but NO word/ xl/ ppt/ entries
            byte[] zipBytes = new byte[100];
            zipBytes[0] = 0x50; zipBytes[1] = 0x4B; zipBytes[2] = 0x03; zipBytes[3] = 0x04;

            var format = FormatDetector.Detect(zipBytes);
            Assert.NotNull(format);
            Assert.Equal(".zip", format.Extension);
        }

        [Fact]
        public void Detect_Json_ShouldDetectCorrectly()
        {
            byte[] jsonBytes = Encoding.UTF8.GetBytes("   \n\t { \"name\": \"SmartFileKit\" }");
            var format = FormatDetector.Detect(jsonBytes);
            Assert.NotNull(format);
            Assert.Equal(".json", format.Extension);
        }

        [Fact]
        public void Detect_Xml_ShouldDetectCorrectly()
        {
            byte[] xmlBytes = Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><root></root>");
            var format = FormatDetector.Detect(xmlBytes);
            Assert.NotNull(format);
            Assert.Equal(".xml", format.Extension);
        }

        [Fact]
        public void Detect_Text_ShouldDetectCorrectly()
        {
            byte[] txtBytes = Encoding.UTF8.GetBytes("This is plain text with no magic bytes but readable ASCII.");
            var format = FormatDetector.Detect(txtBytes);
            Assert.NotNull(format);
            Assert.Equal(".txt", format.Extension);
        }

        [Fact]
        public void Detect_NullOrEmpty_ShouldReturnNull()
        {
            Assert.Null(FormatDetector.Detect((byte[])null));
            Assert.Null(FormatDetector.Detect(new byte[0]));
        }

        [Fact]
        public void Detect_StreamReset_ShouldResetSeekableStream()
        {
            byte[] pngBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
            using (var ms = new MemoryStream(pngBytes))
            {
                var format = FormatDetector.Detect(ms);
                Assert.NotNull(format);
                Assert.Equal(".png", format.Extension);
                Assert.Equal(0, ms.Position); // Verified reset position
            }
        }
    }
}
