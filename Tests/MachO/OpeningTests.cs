using System;
using NUnit.Framework;
using ELFSharp.MachO;

namespace Tests.MachO
{
    [TestFixture]
    public class OpeningTests
    {
        [Test]
        public void ShouldOpenMachO()
        {
            var fileName = Utilities.GetBinaryLocation("simple-mach-o");
            ELFSharp.MachO.MachO machO;
            Assert.AreEqual(MachOResult.OK, MachOReader.TryLoad(fileName, out machO));
        }

        [Test]
        public void ShouldFindCorrectMachine()
        {
            var fileName = Utilities.GetBinaryLocation("simple-mach-o");
            var machO = MachOReader.Load(fileName);
            Assert.AreEqual(Machine.X86_64, machO.Machine);
        }
    }
}

