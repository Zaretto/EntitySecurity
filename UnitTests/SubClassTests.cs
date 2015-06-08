using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    /// <summary>
    /// This version of the reference monitor defines which permission field the Assign operation maps to.
    /// The basic operations (system, world) will use this permission; however the fine grained (that call IsOwnerEquivalent or IsGroupEquivalent)
    /// can further refine the applicability of the group / owner tests to exlcude this operation if required.
    /// </summary>
    public class MyReferenceMonitor : ReferenceMonitor
    {
        public override bool HasPermissionRequiredForOperation(Operation operation, IPermission permission)
        {
            switch (operation)
            {
                case Operation.Assign:
                    return permission.Write;
                default:
                    return base.HasPermissionRequiredForOperation(operation, permission);
            }
        }
    }
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
            var x = Operation.Write.Add(Operation.Read).Add(Operation.Move);
            Assert.IsTrue(x.Contains(Operation.Write));
            Assert.IsTrue(x.Contains(Operation.Read));
            Assert.IsTrue(x.Contains(Operation.Move));

            Assert.IsFalse(x.Contains(Operation.Create));
        }

        /// <summary>
        /// check that the operations can be granted on a per group basis.
        /// </summary>
        [TestMethod]
        public void TestExtensible_Assign()
        {
            //var u1 = new TestUser(1);
            var g1read = new TestGroup(readGroupId1, new Permission(Permissions.RE), Operation.Read);
            var g1write = new TestGroup(writeGroupId1, new Permission(Permissions.W), Operation.Write);
            var g1assign = new TestGroup(new Guid(), new Permission(Permissions.W), Operation.Assign);
            var readWriteUser = new User(Id1, g1read, g1write);
            var readOnlyUser = new User(new Guid(), g1read, null);
            var writeUser = new User(new Guid(), g1read, g1write);
            var assignUser = new User(Id2, g1read, g1assign);

            var o1 = new TestItem(readWriteUser, g1read, g1write, new Protection(0xfff0)); //S:REWD O:REWD G:REWD W:
            o1._groups.Add(g1assign);

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, readWriteUser, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, readOnlyUser, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, readOnlyUser, o1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Assign, assignUser, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, assignUser, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Assign, writeUser, o1));

            readOnlyUser.AddPrivilege(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, readWriteUser, o1));
        }
    }
}