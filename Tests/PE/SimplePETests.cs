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
        public void MZHeaderParserTest()
        {
            ELFSharp.PE.PE pe;
            Assert.IsTrue(PEReader.TryLoad(Utilities.GetBinaryLocation("small-dotnet.exe"), out pe));
            Assert.IsNotNull(pe);

            var mzHeader = pe.MZHeader;
            Assert.IsNotNull(mzHeader);
            Assert.AreEqual(new byte[] {0x4D, 0x5A}, mzHeader.Signature);
            Assert.AreEqual(0x90, mzHeader.ExtraBytes);
            Assert.AreEqual(0x03, mzHeader.Pages);
            Assert.AreEqual(0x00, mzHeader.RelocationItems);
            Assert.AreEqual(0x04, mzHeader.HeaderSize);
            Assert.AreEqual(0x00, mzHeader.MinimumAllocation);
            Assert.AreEqual(0xffff, mzHeader.MaximumAllocation);
            Assert.AreEqual(0, mzHeader.InitialSS);
            Assert.AreEqual(0xb8, mzHeader.InitialSP);
            Assert.AreEqual(0, mzHeader.Checksum);
            Assert.AreEqual(0, mzHeader.InitialIP);
            Assert.AreEqual(0, mzHeader.InitialCS);
            Assert.AreEqual(0x40, mzHeader.RelocationTable);
            Assert.AreEqual(0, mzHeader.Overlay);
            Assert.AreEqual(Enumerable.Repeat(0x00, 4), mzHeader.Reserved);
            Assert.AreEqual(0, mzHeader.OEMId);
            Assert.AreEqual(0, mzHeader.OEMInfo);
            Assert.AreEqual(Enumerable.Repeat(0x00, 10), mzHeader.Reserved2);
            Assert.AreEqual(0x80, mzHeader.PEOffset);
        }


        [Test]
        public void PELoadNotMZ()
        {
            var stream = new MemoryStream(Enumerable.Repeat((byte)0x00, 1024).ToArray());
            Assert.That(() => PEReader.Load(stream), Throws.Exception);
        }
    }
}
