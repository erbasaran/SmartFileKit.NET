using SmartFileKit.Domain;
using SmartFileKit.Validation;
using System.Text;

namespace SmartFileKit.Tests
{
    public class ValidatorTests
    {
        [Fact]
        public void Validate_ValidFile_ShouldPass()
        {
            // A valid PNG file named photo.png
            byte[] fileBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
            var result = FileValidator.Validate(fileBytes, "photo.png")
                .MaxSize(5.MB())
                .AllowedExtensions(".png", ".jpg")
                .AllowedCategories(FileCategory.Image)
                .Execute();

            Assert.True(result.IsValid);
            Assert.Empty(result.Errors);
        }

        [Fact]
        public void Validate_TooLargeFile_ShouldFail()
        {
            // A 10KB PNG file but max size set to 5KB
            byte[] fileBytes = new byte[10240];
            fileBytes[0] = 0x89; fileBytes[1] = 0x50; fileBytes[2] = 0x4E; fileBytes[3] = 0x47;

            var result = FileValidator.Validate(fileBytes, "photo.png")
                .MaxSize(5.KB())
                .Execute();

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("exceeds the maximum limit"));
        }

        [Fact]
        public void Validate_ExtensionNotAllowed_ShouldFail()
        {
            byte[] fileBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
            var result = FileValidator.Validate(fileBytes, "photo.png")
                .AllowedExtensions(".jpg", ".gif")
                .Execute();

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("extension '.png' is not allowed"));
        }

        [Fact]
        public void Validate_CategoryNotAllowed_ShouldFail()
        {
            byte[] fileBytes = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
            var result = FileValidator.Validate(fileBytes, "photo.png")
                .AllowedCategories(FileCategory.Document)
                .Execute();

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("category 'Image' is not allowed"));
        }

        [Fact]
        public void Validate_SpoofedFile_ShouldFail()
        {
            // Named safe.jpg, but contains Executable (MZ) bytes!
            byte[] fileBytes = Encoding.ASCII.GetBytes("MZ\x90\x00\x03\x00\x00\x00...");
            var result = FileValidator.Validate(fileBytes, "safe.jpg")
                .Execute();

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("spoofing") || e.Contains("mismatch"));
        }

        [Fact]
        public void Validate_SpoofedOfficeDoc_ShouldFail()
        {
            // Named report.docx, but is just a generic ZIP file containing malware script rather than word documents
            byte[] fileBytes = new byte[100];
            fileBytes[0] = 0x50; fileBytes[1] = 0x4B; fileBytes[2] = 0x03; fileBytes[3] = 0x04; // ZIP header
                                                                                                // But NO "word/" string inside!

            var result = FileValidator.Validate(fileBytes, "report.docx")
                .Execute();

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("spoofing") || e.Contains("mismatch"));
        }

        [Fact]
        public void Validate_ThrowIfInvalid_ShouldThrowException()
        {
            byte[] fileBytes = Encoding.ASCII.GetBytes("MZ...");
            var validator = FileValidator.Validate(fileBytes, "virus.jpg");

            Assert.Throws<FileValidationException>(() => validator.ThrowIfInvalid());
        }

        [Fact]
        public void Validate_EmptyFileNotAllowed_ShouldFail()
        {
            byte[] fileBytes = new byte[0];
            var result = FileValidator.Validate(fileBytes, "empty.png")
                .Execute();

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("empty"));
        }

        [Fact]
        public void Validate_EmptyFileAllowed_ShouldPass()
        {
            byte[] fileBytes = new byte[0];
            var result = FileValidator.Validate(fileBytes, "empty.png")
                .AllowEmpty()
                .Execute();

            Assert.True(result.IsValid);
        }
    }
}
