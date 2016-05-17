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

            Machine = (MachineType)reader.ReadUInt16();
            NumberOfSections = reader.ReadUInt16();
            var dt = reader.ReadUInt32();
            TimeDateStamp = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(dt);
            PointerToSymbolTable = reader.ReadUInt32();
            NumberOfSymbols = reader.ReadUInt32();
            SizeOfOptionalHeader = reader.ReadUInt16();
            Characteristics = (ImageCharacteristics)reader.ReadUInt16();
        }

        public byte[] Signature { get; private set; }
        public MachineType Machine { get; private set; }
        public ushort NumberOfSections { get; private set; }
        public DateTime TimeDateStamp { get; private set; }
        public uint PointerToSymbolTable { get; private set; }
        public uint NumberOfSymbols { get; private set; }
        public ushort SizeOfOptionalHeader { get; private set; }
        public ImageCharacteristics Characteristics { get; private set; }
        
        public enum MachineType
        {
            IntelX86 = 0x014c,
            AmdX64 = 0x8664,
            MipsR3000 = 0x0162,
            MipsR10000 = 0x0168,
            MipsLittleEndianWCI = 0x0169,
            AlphaAXPOld = 0x0183,
            AlpheAXP = 0x0184,
            HitachiSH3 = 0x01a2,
            HitachiSH3DSP = 0x01a3,
            HitachiSH4 = 0x01a6,
            HitachiSH5 = 0x01a8,
            ArmLittleEndian = 0x01c0,
            Thump = 0x01c2,
            MatsushitaAM33 = 0x01d3,
            PowerPCLittleEndian = 0x01f0,
            PowerPCWithFloatingPoint = 0x01f1,
            IntelIA64 = 0x0200,
            Mips16 = 0x0266,
            Motorola68000 = 0x0268,
            AlphaAXP64 = 0x0284,
            MipsWithFPU = 0x0366,
            Mips16WithFPU = 0x0466,
            EFIByteCode = 0x0ebc,
            Amd64 = 0x8664,
            MitsubishiM32RLittleEndian = 0x9041,
            CLRPureMSIL = 0xc0ee,
        }

        [Flags]
        public enum ImageCharacteristics
        {
            RelocsStripped = 0x0001,
            ExecutableImage = 0x0002,
            LineNumsStripped = 0x0004,
            LocalSymsStripped = 0x0008,
            AggressiveWSTrim = 0x0010,
            LargeAddressAware = 0x0020,
            BytesReversedLo = 0x0080,
            Machine32Bit = 0x0100,
            DebugStripped = 0x0200,
            RemovableRunFromSwap = 0x0400,
            NetRunFromSwap = 0x0800,
            System = 0x1000,
            DLL = 0x2000,
            UPSystemOnly = 0x4000,
            BytesReversedHi = 0x8000,
        }
    }
}
