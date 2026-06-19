using SmartFileKit.Domain;
using SmartFileKit.Validation;
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
        }
    }
}
