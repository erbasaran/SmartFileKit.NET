using SmartFileKit.Domain;

namespace SmartFileKit.Tests
{
    public class FileSizeTests
    {
        [Fact]
        public void FromBytes_ShouldInitializeCorrectly()
        {
            var size = FileSize.FromBytes(1048576);
            Assert.Equal(1048576, size.Bytes);
            Assert.Equal(1024, size.Kilobytes);
            Assert.Equal(1, size.Megabytes);
        }

        [Fact]
        public void ExtensionMethods_ShouldCreateCorrectSizes()
        {
            Assert.Equal(1024, 1.KB().Bytes);
            Assert.Equal(1048576, 1.MB().Bytes);
            Assert.Equal(1073741824, 1.GB().Bytes);
            Assert.Equal(1099511627776, 1.TB().Bytes);
        }

        [Theory]
        [InlineData(500, 2, "500 Bytes")]
        [InlineData(1536, 2, "1.50 KB")]
        [InlineData(1536, 0, "2 KB")]
        [InlineData(1572864, 1, "1.5 MB")] // 1.5 * 1024 * 1024 = 1572864
        [InlineData(5368709120L, 2, "5.00 GB")] // 5 * 1024 * 1024 * 1024 = 5368709120
        [InlineData(2199023255552L, 3, "2.000 TB")] // 2 * 1024 * 1024 * 1024 * 1024 = 2199023255552
        public void ToString_ShouldFormatWithPrecision(long bytes, int precision, string expected)
        {
            var size = new FileSize(bytes);
            Assert.Equal(expected, size.ToString(precision));
        }

        [Fact]
        public void ComparisonOperators_ShouldWorkCorrectly()
        {
            var size1 = 1.MB();
            var size2 = 2.MB();

            Assert.True(size1 < size2);
            Assert.True(size2 > size1);
            Assert.True(size1 <= size2);
            Assert.True(size1 != size2);
            Assert.False(size1 == size2);
        }

        [Fact]
        public void ArithmeticOperators_ShouldWorkCorrectly()
        {
            var size1 = 1.MB();
            var size2 = 2.MB();

            Assert.Equal(3.MB(), size1 + size2);
            Assert.Equal(1.MB(), size2 - size1);
            Assert.Equal(2.MB(), size1 * 2);
            Assert.Equal(1.MB(), size2 / 2);
        }
    }
}
