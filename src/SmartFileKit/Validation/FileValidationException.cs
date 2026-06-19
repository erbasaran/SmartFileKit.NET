using System;
using System.Collections.Generic;

namespace SmartFileKit.Validation
{
    /// <summary>
    /// Exception thrown when file validation fails in the fluent API.
    /// </summary>
    public class FileValidationException : Exception
    {
        /// <summary>
        /// Gets the list of validation errors.
        /// </summary>
        public IReadOnlyList<string> Errors { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileValidationException"/> class with validation errors.
        /// </summary>
        public FileValidationException(IReadOnlyList<string> errors)
            : base($"File validation failed:{Environment.NewLine}- {string.Join(Environment.NewLine + "- ", errors)}")
        {
            Errors = errors ?? throw new ArgumentNullException(nameof(errors));
        }
    }
}
