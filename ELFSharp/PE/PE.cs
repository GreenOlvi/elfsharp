using System.IO;
using ELFSharp.PE.Sections;

namespace ELFSharp.PE
{
    public class PE
    {
        internal PE(string fileName) : this(new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            FileName = fileName;
        }

        internal PE(Stream stream)
        {
            var reader = new BinaryReader(stream);
            MZHeader = new MZHeader(reader);
            _dosStub = reader.ReadBytes((int) (MZHeader.PEOffset - reader.BaseStream.Position));
        }

        public string FileName { get; private set; }

        public MZHeader MZHeader { get; private set; }
        private byte[] _dosStub;

    }
}
