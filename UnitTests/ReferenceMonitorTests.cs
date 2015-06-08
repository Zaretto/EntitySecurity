using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    [TestClass]
    public class ReferenceMonitorTests
    {
        private Guid Id1 = Guid.NewGuid();
        private Guid Id2 = Guid.NewGuid();
        private Guid readGroupId1 = Guid.NewGuid();
        private Guid readGroupId2 = Guid.NewGuid();
        private Guid writeGroupId1 = Guid.NewGuid();
        private Guid writeGroupId2 = Guid.NewGuid();
        private ReferenceMonitor ReferenceMonitor = new ReferenceMonitor();

        [TestMethod]
        public void TestReferenceMonitor()
        {
            //var u1 = new TestUser(1);
            var g1read = new TestGroup(readGroupId1, new Permission(Permissions.RE), Operation.Read);
            var g2read = new TestGroup(readGroupId2, new Permission(Permissions.RE), Operation.Read);
            var g1write = new TestGroup(writeGroupId1, new Permission(Permissions.W), Operation.Write.Add(Operation.Read).Add(Operation.Delete));
            var g2write = new TestGroup(writeGroupId2, new Permission(Permissions.W), Operation.Write);
            var User1 = new User(Id1, g1read, g1write);
            var User2 = new User(Id2, g2read, g2write);

            var protection = new Protection(Permissions.Standard);
            var o1 = new TestItem(User1, g1read, g1write, protection);

            var o2 = new TestItem(User2, g2read, g1write, new Protection(0xff00));
            var o3 = new TestItem(User2, g2read, g1write, new Protection(0xffd1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o3));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Security, User1, o3));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User2, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o2));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Security, User1, o2));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Security, User1, o1));

            User1.AddPrivilege(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o2));
        }
        [TestMethod]
        public void TestReadWriteGroups()
        {
            //var u1 = new TestUser(1);
            var g1read = new TestGroup(readGroupId1, new Permission(Permissions.RE), Operation.Read);
            var g1write = new TestGroup(writeGroupId1, new Permission(Permissions.W), Operation.Read);
            var readWriteUser = new User(Id1, g1read, g1write);
            var readOnlyUser = new User(new Guid(), g1read, null);

            var o1 = new TestItem(readWriteUser, g1read, g1write, new Protection(0xfff0)); //S:REWD O:REWD G:REWD W:


            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, readWriteUser, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, readOnlyUser, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, readOnlyUser, o1));

            readOnlyUser.AddPrivilege(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, readWriteUser, o1));
        }
        [TestMethod]
        public void OwnerProtection()
        {
            //var u1 = new TestUser(1);
            var g1read = new TestGroup(readGroupId1, new Permission(Permissions.RE), Operation.Read);
            var g2read = new TestGroup(readGroupId2, new Permission(Permissions.RE), Operation.Read);
            var g1write = new TestGroup(writeGroupId1, new Permission(Permissions.W), Operation.Write);
            var g2write = new TestGroup(writeGroupId2, new Permission(Permissions.W), Operation.Write);
            var User1 = new User(Id1, g1read, g1write);
            var User2 = new User(Id2, g2read, g2write);

            var protection = new Protection(Permissions.Standard);
            var o1 = new TestItem(User1, g1read, g1write, protection);

            var o2 = new TestItem(User2, g2read, g2write, new Protection(Permission.R, Permission.RWED, Permission.Deny, Permission.Deny));
            var o3 = new TestItem(User2, g2read, g2write, new Protection(Permission.RWED, Permission.RWED, Permission.R, Permission.R));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User2, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o2));

            User1.AddPrivilege(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o2));
        }

        [TestMethod]
        public void Privileges()
        {
            var g1read = new TestGroup(readGroupId1, new Permission(Permissions.RE), Operation.Read);
            var g1write = new TestGroup(writeGroupId1, new Permission(Permissions.W), Operation.Write);
            var User1 = new User(Id1, g1read, g1write);

            // create an object to which the user will have no access
            var protection = new Protection(0);
            var o1 = new TestItem(User1, g1read, g1write, protection);

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Delete, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Security, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Create, User1, o1));

            User1.AddPrivilege(Privilege.READALL);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Delete, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Security, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Create, User1, o1));

            User1.RemovePrivilege(Privilege.READALL);
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Delete, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Security, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Create, User1, o1));

            User1.AddPrivilege(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Delete, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Security, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Create, User1, o1));

            /*
             * remove a different permission and check that access is still permitted
             */
            User1.RemovePrivilege(Privilege.READALL);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Delete, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Security, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Create, User1, o1));

            User1.RemovePrivilege(Privilege.BYPASS);
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Delete, User1, o1));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Security, User1, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Create, User1, o1));
        }
    }
}