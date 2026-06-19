using System;

namespace SmartFileKit.Security
{
    /// <summary>
    /// Holds document metadata extracted from OOXML Office files (docx, xlsx, pptx).
    /// </summary>
    public class OfficeMetadataResult
    {
        /// <summary>
        /// Gets the creator/author of the document.
        /// </summary>
        public string Author { get; }

        /// <summary>
        /// Gets the title of the document.
        /// </summary>
        public string Title { get; }

        /// <summary>
        /// Gets the creation date/time of the document.
        /// </summary>
        public DateTime? CreatedDate { get; }

        /// <summary>
        /// Gets the last modification date/time of the document.
        /// </summary>
        public DateTime? ModifiedDate { get; }

        /// <summary>
        /// Gets the company/organization name associated with the document.
        /// </summary>
        public string Company { get; }

        /// <summary>
        /// Gets a value indicating whether metadata extraction succeeded.
        /// </summary>
        public bool IsValid { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="OfficeMetadataResult"/> class.
        /// </summary>
        public OfficeMetadataResult(
            string author,
            string title,
            DateTime? createdDate,
            DateTime? modifiedDate,
            string company,
            bool isValid)
        {
            Author = author;
            Title = title;
            CreatedDate = createdDate;
            ModifiedDate = modifiedDate;
            Company = company;
            IsValid = isValid;
        }

        /// <summary>
        /// Returns an invalid metadata result.
        /// </summary>
        public static OfficeMetadataResult Invalid() => new OfficeMetadataResult(null, null, null, null, null, false);
    }
}
