using System.IO;
using SmartFileKit.Domain;

namespace SmartFileKit.Analysis
{
    /// <summary>
    /// Builder class for configuring and running the file analysis engine fluent interface.
    /// </summary>
    public class FileAnalyzerBuilder
    {
        private readonly FileAnalysisOptions _options = new FileAnalysisOptions();

        /// <summary>
        /// Configures whether to validate file signatures (magic bytes). Default is true.
        /// </summary>
        public FileAnalyzerBuilder ValidateSignature(bool validate = true)
        {
            _options.ValidateSignature = validate;
            return this;
        }

        /// <summary>
        /// Configures whether to validate MIME mappings and client content type. Default is true.
        /// </summary>
        public FileAnalyzerBuilder ValidateMime(bool validate = true)
        {
            _options.ValidateMime = validate;
            return this;
        }

        /// <summary>
        /// Configures whether to inspect archive structures (e.g. ZIP/Office files). Default is true.
        /// </summary>
        public FileAnalyzerBuilder ValidateStructure(bool validate = true)
        {
            _options.ValidateStructure = validate;
            return this;
        }

        /// <summary>
        /// Configures whether to calculate the security risk score. Default is true.
        /// </summary>
        public FileAnalyzerBuilder CalculateRiskScore(bool calculate = true)
        {
            _options.CalculateRiskScore = calculate;
            return this;
        }

        /// <summary>
        /// Configures whether to calculate Shannon Entropy for identifying obfuscated content. Default is false.
        /// </summary>
        public FileAnalyzerBuilder CheckEntropy(bool check = true, double threshold = 7.5, int maxBytes = 1024 * 1024)
        {
            _options.CheckEntropy = check;
            _options.EntropyThreshold = threshold;
            _options.MaxBytesForEntropy = maxBytes;
            return this;
        }

        /// <summary>
        /// Executes file analysis on the specified stream.
        /// </summary>
        public FileAnalysisReport Analyze(Stream stream, string fileName = null, string contentType = null)
        {
            var analyzer = new FileAnalyzer(_options);
            return analyzer.AnalyzeInternal(stream, fileName, contentType);
        }
    }
}
