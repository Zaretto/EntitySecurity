using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    [TestClass]
    public class ReferenceMonitorTests
    {
        Guid Id1 = Guid.NewGuid();
        Guid Id2 = Guid.NewGuid();
        Guid GroupId1 = Guid.NewGuid();
        Guid GroupId2 = Guid.NewGuid();

        [TestMethod]
        public void TestReferenceMonitor()
        {
            //var u1 = new TestUser(1);
            var g1 = new TestGroup(GroupId1);
            var g2 = new TestGroup(GroupId2);
            var User1 = new User(Id1, Id1);
            var User2 = new User(Id2, Id2);

            var protection = new Protection(Protection.Standard);
            var o1 = new TestItem(User1, g1, protection);

            var o2 = new TestItem(User2, g2, new Protection(0xff00));
            var o3 = new TestItem(User2, g2, new Protection(0xffd1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User2, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o2));

            User1.Privileges.Add(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o2));

        }
        [TestMethod]
        public void OwnerProtection()
        {
            //var u1 = new TestUser(1);
            var g1 = new TestGroup(GroupId1);
            var g2 = new TestGroup(GroupId2);
            var User1 = new User(Id1, Id1);
            var User2 = new User(Id2, Id2);

            var protection = new Protection(Protection.Standard);
            var o1 = new TestItem(User1, g1, protection);

            var o2 = new TestItem(User2, g2, new Protection(Permission.R, Permission.RWED, Permission.Deny, Permission.Deny));
            var o3 = new TestItem(User2, g2, new Protection(Permission.RWED, Permission.RWED, Permission.R, Permission.R));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Write, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User2, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o2));

            User1.Privileges.Add(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Operation.Read, User1, o2));

        }
    }
}
