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
            _reader = new BinaryReader(stream);
            ReadMZHeader();
        }

        public string FileName { get; private set; }

        private readonly BinaryReader _reader;
        private MZHeader _mzHeader;

        private void ReadMZHeader()
        {
            _mzHeader = new MZHeader(_reader);
        }
    }
}
