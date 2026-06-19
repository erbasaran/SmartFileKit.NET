using System;
using System.Collections.Generic;
using System.IO;
using SmartFileKit.Domain;
using SmartFileKit.Validation;

namespace SmartFileKit.Security
{
    /// <summary>
    /// Implements reusable, fluent security policies for validating file uploads.
    /// </summary>
    public class UploadPolicy
    {
        private FileSize? _maxSize;
        private readonly List<string> _allowedExtensions = new List<string>();
        private readonly List<string> _blockedExtensions = new List<string>();
        private readonly List<FileCategory> _allowedCategories = new List<FileCategory>();
        private readonly List<FileCategory> _blockedCategories = new List<FileCategory>();
        private bool _enforceSignature = true;

        private UploadPolicy() { }

        /// <summary>
        /// Creates a new instance of the <see cref="UploadPolicy"/> configuration builder.
        /// </summary>
        public static UploadPolicy Create() => new UploadPolicy();

        /// <summary>
        /// Restricts uploads to files below the maximum size limit.
        /// </summary>
        public UploadPolicy MaxSize(FileSize size)
        {
            _maxSize = size;
            return this;
        }

        /// <summary>
        /// Restricts uploads to the specified allowed extensions.
        /// </summary>
        public UploadPolicy AllowExtensions(params string[] extensions)
        {
            if (extensions != null) _allowedExtensions.AddRange(extensions);
            return this;
        }

        /// <summary>
        /// Restricts uploads by blocking specified extensions.
        /// </summary>
        public UploadPolicy BlockExtensions(params string[] extensions)
        {
            if (extensions != null) _blockedExtensions.AddRange(extensions);
            return this;
        }

        /// <summary>
        /// Restricts uploads to specified file categories.
        /// </summary>
        public UploadPolicy AllowCategories(params FileCategory[] categories)
        {
            if (categories != null) _allowedCategories.AddRange(categories);
            return this;
        }

        /// <summary>
        /// Restricts uploads by blocking specified file categories.
        /// </summary>
        public UploadPolicy BlockCategories(params FileCategory[] categories)
        {
            if (categories != null) _blockedCategories.AddRange(categories);
            return this;
        }

        /// <summary>
        /// Fluent shortcut to allow standard web image extensions and the image category.
        /// </summary>
        public UploadPolicy AllowImages()
        {
            AllowCategories(FileCategory.Image);
            AllowExtensions(".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg");
            return this;
        }

        /// <summary>
        /// Configures whether byte headers / magic signatures are actively verified. Default is true.
        /// </summary>
        public UploadPolicy EnforceSignature(bool enforce = true)
        {
            _enforceSignature = enforce;
            return this;
        }

        /// <summary>
        /// Executes validation of a stream and filename against the configured policy.
        /// </summary>
        public FileValidationResult Validate(Stream stream, string fileName, string contentType = null)
        {
            var validator = FileValidator.Validate(stream, fileName, contentType)
                .VerifySignature(_enforceSignature);

            if (_maxSize.HasValue)
            {
                validator.MaxSize(_maxSize.Value);
            }

            if (_allowedExtensions.Count > 0)
            {
                validator.AllowedExtensions(_allowedExtensions.ToArray());
            }

            if (_blockedExtensions.Count > 0)
            {
                validator.BlockedExtensions(_blockedExtensions.ToArray());
            }

            if (_allowedCategories.Count > 0)
            {
                validator.AllowedCategories(_allowedCategories.ToArray());
            }

            if (_blockedCategories.Count > 0)
            {
                validator.BlockedCategories(_blockedCategories.ToArray());
            }

            return validator.Execute();
        }
    }
}
