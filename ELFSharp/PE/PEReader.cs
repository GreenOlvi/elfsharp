using System;
using System.IO;

namespace ELFSharp.PE
{
    public static class PEReader
    {
        public static PE Load(string fileName)
        {
            PE pe;
            if(!TryLoad(fileName, out pe))
            {
                throw new ArgumentException("Given file is not proper PE file.");
            }
            return pe;
        }

        public static PE Load(Stream stream)
        {
            return new PE(stream);
        }

        public static bool TryLoad(string fileName, out PE pe)
        {
            pe = null;
            try
            {
                pe = new PE(fileName);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }
    }
}
