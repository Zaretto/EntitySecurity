using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TestObjects;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
   
    [TestClass]
    public class SubClassTests
    {
        private Guid Id1 = Guid.NewGuid();
        private Guid Id2 = Guid.NewGuid();
        private Guid readGroupId1 = Guid.NewGuid();
        private Guid readGroupId2 = Guid.NewGuid();
        private Guid writeGroupId1 = Guid.NewGuid();
        private Guid writeGroupId2 = Guid.NewGuid();
        private ReferenceMonitor ReferenceMonitor = new MyReferenceMonitor();

        /// <summary>
        /// checks the operation field is operating correctly.
        /// </summary>
        [TestMethod]
        public void OperationManipulation()
        {
            var x = IControlledObjectOperation.Write.Append(IControlledObjectOperation.Read).Append(IControlledObjectOperation.Move);
            Assert.IsTrue(x.Contains(IControlledObjectOperation.Write));
            Assert.IsTrue(x.Contains(IControlledObjectOperation.Read));
            Assert.IsTrue(x.Contains(IControlledObjectOperation.Move));

            Assert.IsFalse(x.Contains(IControlledObjectOperation.Create));
        }

        /// <summary>
        /// check that the operations can be granted on a per group basis.
        /// </summary>
        [TestMethod]
        public void TestExtensible_Assign()
        {
            //var u1 = new TestUser(1);
            var g1read = new TestGroup(readGroupId1, IControlledObjectOperation.Read);
            var g1write = new TestGroup(writeGroupId1, IControlledObjectOperation.Write);
            var g1assign = new TestGroup(new Guid(), IControlledObjectOperation.Assign);
            var readWriteUser = new User(Id1, g1read, g1write);
            var readOnlyUser = new User(new Guid(), g1read, null);
            var writeUser = new User(new Guid(), g1read, g1write);
            var assignUser = new User(Id2, g1read, g1assign);

            var o1 = new TestItem(readWriteUser, g1read, g1write, new Protection(0xfff0)); //S:REWD O:REWD G:REWD W:
            o1._groups.Add(g1assign);

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.IControlledObjectOperation.Read, readWriteUser, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.IControlledObjectOperation.Read, readOnlyUser, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.IControlledObjectOperation.Write, readOnlyUser, o1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.IControlledObjectOperation.Assign, assignUser, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.IControlledObjectOperation.Write, assignUser, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.IControlledObjectOperation.Assign, writeUser, o1));

            readOnlyUser.AddPrivilege(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.IControlledObjectOperation.Write, readWriteUser, o1));
        }
    }
}