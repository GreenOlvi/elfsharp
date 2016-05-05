using System;
using System.IO;
using System.Linq;

namespace ELFSharp.PE.Sections
{
    public class PEHeader
    {
        private static readonly byte[] SignatureBytes = {0x50, 0x45, 0x00, 0x00}; // "PE\x00\x00"

        public PEHeader(BinaryReader reader)
        {
            Signature = reader.ReadBytes(4);
            if(!Signature.SequenceEqual(SignatureBytes))
            {
                throw new Exception("Not a PE header!");
            }
        }

        public byte[] Signature { get; private set; }
    }
}
