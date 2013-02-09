using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    [TestClass]
    public class ReferenceMonitorTests
    {
        [TestMethod]
        public void TestReferenceMonitor()
        {
            //var u1 = new TestUser(1);
            var g1 = new TestGroup(11);
            var g2 = new TestGroup(22);
            var User1 = new User(11, 11);
            var User2 = new User(22, 22);

            var protection = new Protection(Protection.Standard);
            var o1 = new TestItem(User1, g1, protection);

            var o2 = new TestItem(User2, g2, new Protection(0xff00));
            var o3 = new TestItem(User2, g2, new Protection(0xff11));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User1, o1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Write, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Write, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User2, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User1, o2));

            User1.Privileges.Add(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User1, o2));

        }
        [TestMethod]
        public void OwnerProtection()
        {
            //var u1 = new TestUser(1);
            var g1 = new TestGroup(11);
            var g2 = new TestGroup(22);
            var User1 = new User(11, 11);
            var User2 = new User(22, 22);

            var protection = new Protection(Protection.Standard);
            var o1 = new TestItem(User1, g1, protection);

            var o2 = new TestItem(User2, g2, new Protection(Permission.R, Permission.RWED, Permission.Deny, Permission.Deny));
            var o3 = new TestItem(User2, g2, new Protection(Permission.RWED, Permission.RWED, Permission.R, Permission.R));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User1, o1));

            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Write, User1, o3));
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Write, User2, o3));

            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User2, o1));
            Assert.IsFalse(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User1, o2));

            User1.Privileges.Add(Privilege.BYPASS);
            Assert.IsTrue(ReferenceMonitor.IsPermitted(Zaretto.Security.Action.Read, User1, o2));

        }
    }
}
