using System;
using System.IO;
using System.Linq;
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

        [Test]
        public void PELoadNotMZ()
        {
            var stream = new MemoryStream(Enumerable.Repeat((byte)0x00, 64).ToArray());
            Assert.That(() => PEReader.Load(stream), Throws.Exception);
        }
    }
}
