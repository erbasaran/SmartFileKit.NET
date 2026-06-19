namespace SmartFileKit.Tests
{
    public class FileNameTests
    {
        [Theory]
        [InlineData("özel dosya (1).png", "ozel dosya (1).png")]
        [InlineData("Şemsi Paşa Pasajı.docx", "Semsi Pasa Pasaji.docx")]
        [InlineData("çığlık_öğrenci_türkçe.jpg", "ciglik_ogrenci_turkce.jpg")]
        [InlineData("IıİiĞğÜüŞşÖöÇç.pdf", "IiIiGgUuSsOoCc.pdf")]
        public void Sanitize_ShouldNormalizeTurkishCharacters(string input, string expected)
        {
            var result = FileName.Sanitize(input);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("file/name.txt", "file_name.txt")]
        [InlineData("file\\name.png", "file_name.png")]
        [InlineData("invalid*char?.pdf", "invalid_char_.pdf")]
        [InlineData("a:b*c?d\"e<f>g|h.txt", "a_b_c_d_e_f_g_h.txt")]
        public void Sanitize_ShouldRemoveInvalidCharactersAndSeparators(string input, string expected)
        {
            var result = FileName.Sanitize(input);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("../../../etc/passwd", "etc_passwd")]
        [InlineData("..\\..\\windows\\system32.dll", "windows_system32.dll")]
        public void Sanitize_ShouldProtectAgainstPathTraversal(string input, string expected)
        {
            var result = FileName.Sanitize(input);
            Assert.Equal(expected, result);
            Assert.DoesNotContain("/", result);
            Assert.DoesNotContain("\\", result);
        }

        [Theory]
        [InlineData("CON.txt", "_CON.txt")]
        [InlineData("nul", "_nul")]
        [InlineData("PRN.pdf", "_PRN.pdf")]
        [InlineData("com1.zip", "_com1.zip")]
        public void Sanitize_ShouldProtectWindowsReservedNames(string input, string expected)
        {
            var result = FileName.Sanitize(input);
            Assert.Equal(expected, result);
        }

        [Fact]
        public void Sanitize_ShouldTruncateLongFileNames()
        {
            string longName = new string('a', 300) + ".txt";
            var result = FileName.Sanitize(longName);
            Assert.Equal(255, result.Length);
            Assert.EndsWith(".txt", result);
        }

        [Theory]
        [InlineData(null, "file")]
        [InlineData("", "file")]
        [InlineData("   ", "file")]
        [InlineData("/", "file")]
        [InlineData("???", "file")]
        public void Sanitize_ShouldReturnFallbackForEmptyNames(string input, string expected)
        {
            var result = FileName.Sanitize(input);
            Assert.Equal(expected, result);
        }
    }
}
