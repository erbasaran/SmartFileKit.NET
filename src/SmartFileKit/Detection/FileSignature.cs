using System;

namespace SmartFileKit.Detection
{
    /// <summary>
    /// Represents a magic bytes signature used for detecting file types.
    /// </summary>
    public class FileSignature
    {
        /// <summary>
        /// Gets the expected sequence of magic bytes.
        /// </summary>
        public byte[] MagicBytes { get; }

        /// <summary>
        /// Gets the start offset in the stream/buffer where the signature resides.
        /// </summary>
        public int Offset { get; }

        /// <summary>
        /// Gets the optional bitmask applied to the checked bytes.
        /// </summary>
        public byte[] Mask { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="FileSignature"/> class.
        /// </summary>
        /// <param name="magicBytes">The magic bytes sequence.</param>
        /// <param name="offset">The starting byte index of the signature.</param>
        /// <param name="mask">The optional bitmask.</param>
        public FileSignature(byte[] magicBytes, int offset = 0, byte[] mask = null)
        {
            MagicBytes = magicBytes ?? throw new ArgumentNullException(nameof(magicBytes));
            Offset = offset;
            Mask = mask;
        }

        /// <summary>
        /// Determines whether the given buffer matches this signature.
        /// </summary>
        /// <param name="buffer">The file byte buffer to check.</param>
        /// <returns>True if the buffer matches the signature; otherwise, false.</returns>
        public bool Matches(byte[] buffer)
        {
            if (buffer == null || buffer.Length < Offset + MagicBytes.Length)
                return false;

            for (int i = 0; i < MagicBytes.Length; i++)
            {
                byte fileByte = buffer[Offset + i];
                byte magicByte = MagicBytes[i];

                if (Mask != null && Mask.Length > i)
                {
                    if ((fileByte & Mask[i]) != magicByte)
                        return false;
                }
                else
                {
                    if (fileByte != magicByte)
                        return false;
                }
            }

            return true;
        }
    }
}
