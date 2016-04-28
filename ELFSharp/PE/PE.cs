namespace ELFSharp.PE
{
    public class PE
    {
        internal PE(string fileName)
        {
            FileName = fileName;
        }

        public string FileName { get; private set; }
    }
}
