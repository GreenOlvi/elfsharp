using ELFSharp.PE;
using NUnit.Framework;

namespace Tests.PE
{
    [TestFixture]
    class SimplePETests
    {
        [Test]
        public void PELoadTest()
        {
            ELFSharp.PE.PE pe;
            Assert.IsTrue(PEReader.TryLoad(Utilities.GetBinaryLocation("small-dotnet.exe"), out pe));
            Assert.IsNotNull(pe);
        }
    }
}
