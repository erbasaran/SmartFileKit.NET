using System.IO;

namespace SmartFileKit.Analysis.Archives
{
    /// <summary>
    /// Defines the contract for archive content inspection.
    /// </summary>
    public interface IArchiveInspector
    {
        /// <summary>
        /// Determines whether this inspector supports the specified file extension or type.
        /// </summary>
        bool CanInspect(string extension);

        /// <summary>
        /// Inspects the archive content from the given stream.
        /// </summary>
        ArchiveInspectionResult Inspect(Stream stream);
    }
}
