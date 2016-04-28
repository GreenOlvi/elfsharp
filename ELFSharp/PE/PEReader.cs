using System;

namespace ELFSharp.PE
{
    public static class PEReader
    {
        public static PE Load(string fileName)
        {
            PE pe;
            if (!TryLoad(fileName, out pe))
            {
                throw new ArgumentException("Given file is not proper PE file.");
            }
            return pe;
        }

        public static bool TryLoad(string fileName, out PE pe)
        {
            pe = new PE(fileName);
            return true;
        }
    }
}
