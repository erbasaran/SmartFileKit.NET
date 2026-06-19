using System.Collections.Generic;

namespace SmartFileKit.Validation
{
    /// <summary>
    /// Represents the result of a file validation execution.
    /// </summary>
    public class FileValidationResult
    {
        /// <summary>
        /// Gets a value indicating whether the file satisfies all validation constraints.
        /// </summary>
        public bool IsValid => Errors.Count == 0;

        /// <summary>
        /// Gets the collection of error messages accumulated during validation.
        /// </summary>
        public IReadOnlyList<string> Errors { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileValidationResult"/> class.
        /// </summary>
        public FileValidationResult(IReadOnlyList<string> errors)
        {
            Errors = errors ?? new List<string>().AsReadOnly();
        }
    }
}
