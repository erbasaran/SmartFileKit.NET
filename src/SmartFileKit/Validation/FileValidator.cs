using SmartFileKit.Detection;
using SmartFileKit.Domain;
using System;
using System.Collections.Generic;
using System.IO;

namespace SmartFileKit.Validation
{
    /// <summary>
    /// Fluent API builder for validating files based on size, extension, MIME type, category, and signatures.
    /// </summary>
    public class FileValidator
    {
        private readonly Stream _stream;
        private readonly string _fileName;
        private readonly string _contentType;
        private readonly bool _ownsStream;
        private readonly List<string> _errors = new List<string>();

        // Configuration rules
        private FileSize? _maxSize;
        private FileSize? _minSize;
        private HashSet<string> _allowedExtensions;
        private HashSet<string> _blockedExtensions;
        private HashSet<string> _allowedMimeTypes;
        private HashSet<string> _blockedMimeTypes;
        private HashSet<FileCategory> _allowedCategories;
        private HashSet<FileCategory> _blockedCategories;
        private bool _verifySignature = true;
        private bool _allowEmpty = false;

        private FileValidator(Stream stream, string fileName, string contentType, bool ownsStream = false)
        {
            _stream = stream;
            _fileName = fileName;
            _contentType = contentType;
            _ownsStream = ownsStream;
        }

        /// <summary>
        /// Starts the validation pipeline for a stream.
        /// </summary>
        public static FileValidator Validate(Stream stream, string fileName = null, string contentType = null)
        {
            return new FileValidator(stream, fileName, contentType);
        }

        /// <summary>
        /// Starts the validation pipeline for a byte array.
        /// </summary>
        public static FileValidator Validate(byte[] bytes, string fileName = null, string contentType = null)
        {
            var stream = bytes != null ? new MemoryStream(bytes) : null;
            return new FileValidator(stream, fileName, contentType, ownsStream: true);
        }

        /// <summary>
        /// Starts the validation pipeline for a local file path.
        /// </summary>
        public static FileValidator Validate(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                var validator = new FileValidator(null, null, null);
                validator._errors.Add("File path cannot be null or empty.");
                return validator;
            }

            if (!File.Exists(filePath))
            {
                var validator = new FileValidator(null, Path.GetFileName(filePath), null);
                validator._errors.Add($"File does not exist at path: '{filePath}'.");
                return validator;
            }

            try
            {
                var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                return new FileValidator(stream, Path.GetFileName(filePath), null, ownsStream: true);
            }
            catch (Exception ex)
            {
                var validator = new FileValidator(null, Path.GetFileName(filePath), null);
                validator._errors.Add($"Failed to open file stream: {ex.Message}");
                return validator;
            }
        }

        /// <summary>
        /// Starts the validation pipeline for a FileInfo object.
        /// </summary>
        public static FileValidator Validate(FileInfo fileInfo)
        {
            if (fileInfo == null)
            {
                var validator = new FileValidator(null, null, null);
                validator._errors.Add("FileInfo parameter is null.");
                return validator;
            }
            return Validate(fileInfo.FullName);
        }

        /// <summary>
        /// Validates that the file size does not exceed the maximum allowed size.
        /// </summary>
        public FileValidator MaxSize(FileSize size)
        {
            _maxSize = size;
            return this;
        }

        /// <summary>
        /// Validates that the file size is not below the minimum allowed size.
        /// </summary>
        public FileValidator MinSize(FileSize size)
        {
            _minSize = size;
            return this;
        }

        /// <summary>
        /// Validates that the file extension is among the allowed extensions.
        /// </summary>
        public FileValidator AllowedExtensions(params string[] extensions)
        {
            if (extensions != null && extensions.Length > 0)
            {
                _allowedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var ext in extensions)
                {
                    string clean = ext.Trim();
                    if (!clean.StartsWith(".", StringComparison.Ordinal)) clean = "." + clean;
                    _allowedExtensions.Add(clean);
                }
            }
            return this;
        }

        /// <summary>
        /// Validates that the file extension is not among the blocked extensions.
        /// </summary>
        public FileValidator BlockedExtensions(params string[] extensions)
        {
            if (extensions != null && extensions.Length > 0)
            {
                _blockedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var ext in extensions)
                {
                    string clean = ext.Trim();
                    if (!clean.StartsWith(".", StringComparison.Ordinal)) clean = "." + clean;
                    _blockedExtensions.Add(clean);
                }
            }
            return this;
        }

        /// <summary>
        /// Validates that the MIME type is among the allowed MIME types.
        /// </summary>
        public FileValidator AllowedMimeTypes(params string[] mimeTypes)
        {
            if (mimeTypes != null && mimeTypes.Length > 0)
            {
                _allowedMimeTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var mime in mimeTypes)
                {
                    _allowedMimeTypes.Add(mime.Trim());
                }
            }
            return this;
        }

        /// <summary>
        /// Validates that the MIME type is not among the blocked MIME types.
        /// </summary>
        public FileValidator BlockedMimeTypes(params string[] mimeTypes)
        {
            if (mimeTypes != null && mimeTypes.Length > 0)
            {
                _blockedMimeTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var mime in mimeTypes)
                {
                    _blockedMimeTypes.Add(mime.Trim());
                }
            }
            return this;
        }

        /// <summary>
        /// Validates that the file's category is among the allowed categories.
        /// </summary>
        public FileValidator AllowedCategories(params FileCategory[] categories)
        {
            if (categories != null && categories.Length > 0)
            {
                _allowedCategories = new HashSet<FileCategory>(categories);
            }
            return this;
        }

        /// <summary>
        /// Validates that the file's category is not among the blocked categories.
        /// </summary>
        public FileValidator BlockedCategories(params FileCategory[] categories)
        {
            if (categories != null && categories.Length > 0)
            {
                _blockedCategories = new HashSet<FileCategory>(categories);
            }
            return this;
        }

        /// <summary>
        /// Configures whether to run actual content signature verification (magic bytes). Default is true.
        /// </summary>
        public FileValidator VerifySignature(bool verify = true)
        {
            _verifySignature = verify;
            return this;
        }

        /// <summary>
        /// Configures whether empty files (0 bytes) are allowed. Default is false.
        /// </summary>
        public FileValidator AllowEmpty(bool allow = true)
        {
            _allowEmpty = allow;
            return this;
        }

        /// <summary>
        /// Executes validation logic and returns the validation result.
        /// Closes internal stream if it was opened by the validator itself.
        /// </summary>
        public FileValidationResult Execute()
        {
            try
            {
                if (_errors.Count > 0)
                {
                    return new FileValidationResult(_errors.AsReadOnly());
                }

                if (_stream == null)
                {
                    _errors.Add("File stream is null or unavailable.");
                    return new FileValidationResult(_errors.AsReadOnly());
                }

                long length;
                try
                {
                    length = _stream.Length;
                }
                catch (Exception ex)
                {
                    _errors.Add($"Failed to retrieve stream length: {ex.Message}");
                    return new FileValidationResult(_errors.AsReadOnly());
                }

                // 1. Size Validation
                if (length == 0 && !_allowEmpty)
                {
                    _errors.Add("File is empty (0 bytes).");
                }

                if (_maxSize.HasValue && length > _maxSize.Value.Bytes)
                {
                    _errors.Add($"File size exceeds the maximum limit of {_maxSize.Value}. Actual size: {new FileSize(length)}.");
                }

                if (_minSize.HasValue && length < _minSize.Value.Bytes)
                {
                    _errors.Add($"File size is below the minimum limit of {_minSize.Value}. Actual size: {new FileSize(length)}.");
                }

                // 2. Extension Parsing
                string fileExt = string.Empty;
                if (!string.IsNullOrEmpty(_fileName))
                {
                    fileExt = Path.GetExtension(_fileName).Trim().ToLowerInvariant();
                }

                if (_allowedExtensions != null && !string.IsNullOrEmpty(fileExt))
                {
                    if (!_allowedExtensions.Contains(fileExt))
                    {
                        _errors.Add($"File extension '{fileExt}' is not allowed.");
                    }
                }

                if (_blockedExtensions != null && !string.IsNullOrEmpty(fileExt))
                {
                    if (_blockedExtensions.Contains(fileExt))
                    {
                        _errors.Add($"File extension '{fileExt}' is blocked.");
                    }
                }

                // 3. MIME validation (from ContentType or mapped from extension)
                string mimeType = _contentType;
                if (string.IsNullOrEmpty(mimeType) && !string.IsNullOrEmpty(fileExt))
                {
                    mimeType = MimeMapper.GetMimeType(fileExt);
                }

                if (_allowedMimeTypes != null && !string.IsNullOrEmpty(mimeType))
                {
                    if (!_allowedMimeTypes.Contains(mimeType))
                    {
                        _errors.Add($"MIME type '{mimeType}' is not allowed.");
                    }
                }

                if (_blockedMimeTypes != null && !string.IsNullOrEmpty(mimeType))
                {
                    if (_blockedMimeTypes.Contains(mimeType))
                    {
                        _errors.Add($"MIME type '{mimeType}' is blocked.");
                    }
                }

                // 4. File Signature Mismatch (Spoofing) Validation
                FileFormatInfo detectedFormat = null;
                if (_verifySignature && length > 0)
                {
                    detectedFormat = FormatDetector.Detect(_stream);

                    if (detectedFormat != null)
                    {
                        if (!string.IsNullOrEmpty(fileExt))
                        {
                            var expectedFormat = FindFormatByExtension(fileExt);
                            if (expectedFormat != null)
                            {
                                // Check if the MIME types differ (e.g. extension says image/jpeg but header says application/x-msdownload)
                                if (expectedFormat.MimeType != detectedFormat.MimeType)
                                {
                                    _errors.Add($"File signature mismatch detected (Spoofing). File extension suggests '{fileExt}' ({expectedFormat.Category}), but actual content matches '{detectedFormat.Extension}' ({detectedFormat.Category}).");
                                }
                            }
                            else
                            {
                                // The extension is unregistered, but the content matched a registered executable or other format
                                _errors.Add($"File signature mismatch detected (Spoofing). Extension '{fileExt}' is unrecognized, but actual content matches '{detectedFormat.Extension}' ({detectedFormat.Category}).");
                            }
                        }
                    }
                    else
                    {
                        // No format was detected by signature.
                        // If the extension expects a signature (e.g. PNG, PDF, ZIP), the file is corrupted or spoofed.
                        if (!string.IsNullOrEmpty(fileExt))
                        {
                            var expectedFormat = FindFormatByExtension(fileExt);
                            if (expectedFormat != null && expectedFormat.Signatures.Count > 0)
                            {
                                _errors.Add($"File signature verification failed. The file expects signature for '{fileExt}' but lacks a valid header.");
                            }
                        }
                    }
                }

                // 5. Category Validation
                FileCategory activeCategory = FileCategory.Unknown;
                if (detectedFormat != null)
                {
                    activeCategory = detectedFormat.Category;
                }
                else if (!string.IsNullOrEmpty(fileExt))
                {
                    activeCategory = MimeMapper.GetCategory(fileExt);
                }

                if (_allowedCategories != null)
                {
                    if (!_allowedCategories.Contains(activeCategory))
                    {
                        _errors.Add($"File category '{activeCategory}' is not allowed.");
                    }
                }

                if (_blockedCategories != null)
                {
                    if (_blockedCategories.Contains(activeCategory))
                    {
                        _errors.Add($"File category '{activeCategory}' is blocked.");
                    }
                }

                return new FileValidationResult(_errors.AsReadOnly());
            }
            finally
            {
                if (_ownsStream && _stream != null)
                {
                    try
                    {
                        _stream.Dispose();
                    }
                    catch
                    {
                        // Ignore stream dispose error
                    }
                }
            }
        }

        /// <summary>
        /// Executes validation logic and throws a FileValidationException if validation fails.
        /// </summary>
        public void ThrowIfInvalid()
        {
            var result = Execute();
            if (!result.IsValid)
            {
                throw new FileValidationException(result.Errors);
            }
        }

        private FileFormatInfo FindFormatByExtension(string ext)
        {
            if (string.IsNullOrEmpty(ext)) return null;
            string clean = ext.Trim();
            if (!clean.StartsWith(".", StringComparison.Ordinal)) clean = "." + clean;
            clean = clean.ToLowerInvariant();

            foreach (var format in FileFormatRegistry.Formats)
            {
                if (format.Extension == clean)
                    return format;
            }
            return null;
        }
    }
}
