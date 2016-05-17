using System;
using System.IO;
using System.Linq;

namespace ELFSharp.PE.Sections
{
    public class MZHeader
    {
        private static readonly byte[] SignatureBytes = {0x4D, 0x5A}; // "MZ"

        public MZHeader(BinaryReader reader)
        {
            Signature = reader.ReadBytes(2);
            if(!Signature.SequenceEqual(SignatureBytes))
            {
                throw new Exception("Not a MZ header.");
            }

            ExtraBytes = reader.ReadUInt16();
            Pages = reader.ReadUInt16();
            RelocationItems = reader.ReadUInt16();
            HeaderSize = reader.ReadUInt16();
            MinimumAllocation = reader.ReadUInt16();
            MaximumAllocation = reader.ReadUInt16();
            InitialSS = reader.ReadUInt16();
            InitialSP = reader.ReadUInt16();
            Checksum = reader.ReadUInt16();
            InitialIP = reader.ReadUInt16();
            InitialCS = reader.ReadUInt16();
            RelocationTable = reader.ReadUInt16();
            Overlay = reader.ReadUInt16();

            Reserved = Enumerable.Range(0, 4)
                .Select(i => reader.ReadUInt16())
                .ToArray();

            OEMId = reader.ReadUInt16();
            OEMInfo = reader.ReadUInt16();

            Reserved2 = Enumerable.Range(0, 10)
                .Select(i => reader.ReadUInt16())
                .ToArray();

            PEOffset = reader.ReadUInt32();
        }

        public byte[] Signature { get; private set; }
        public UInt16 ExtraBytes { get; private set; }
        public UInt16 Pages { get; private set; }
        public UInt16 RelocationItems { get; private set; }
        public UInt16 HeaderSize { get; private set; }
        public UInt16 MinimumAllocation { get; private set; }
        public UInt16 MaximumAllocation { get; private set; }
        public UInt16 InitialSS { get; private set; }
        public UInt16 InitialSP { get; private set; }
        public UInt16 Checksum { get; private set; }
        public UInt16 InitialIP { get; private set; }
        public UInt16 InitialCS { get; private set; }
        public UInt16 RelocationTable { get; private set; }
        public UInt16 Overlay { get; private set; }
        public UInt16[] Reserved { get; private set; }
        public UInt16 OEMId { get; private set; }
        public UInt16 OEMInfo { get; private set; }
        public UInt16[] Reserved2 { get; private set; }
        public UInt32 PEOffset { get; private set; }
    }
}
