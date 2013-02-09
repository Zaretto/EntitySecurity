using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Zaretto.Security;
using System.Collections.Specialized;

namespace ReferenceMonitorTests
{
    /// <summary>
    /// Summary description for UnitTest2
    /// </summary>
    [TestClass]
    public class PermissionTests
    {
        public PermissionTests()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:
        //
        // Use ClassInitialize to run code before running the first test in the class
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        /// <summary>
        /// tests the all the permutations of a permission
        /// </summary>
        [TestMethod]
        public void TestPermissions()
        {
            Permission p1;

            p1 = new Permission(true, false, false, false);
            Assert.IsTrue(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsFalse(p1.Delete);

            p1 = new Permission(false, true, false, false);
            Assert.IsFalse(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsFalse(p1.Delete);

            p1 = new Permission(true, true, false, false);
            Assert.IsTrue(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsFalse(p1.Delete);

            p1 = new Permission(false, false, true, false);
            Assert.IsFalse(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsFalse(p1.Delete);

            p1 = new Permission(true, false, true, false);
            Assert.IsTrue(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsFalse(p1.Delete);

            p1 = new Permission(false, true, true, false);
            Assert.IsFalse(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsFalse(p1.Delete);

            p1 = new Permission(true, true, true, false);
            Assert.IsTrue(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsFalse(p1.Delete);

            p1 = new Permission(false, false, false, true);
            Assert.IsFalse(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1 = new Permission(true, false, false, true);
            Assert.IsTrue(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1 = new Permission(false, true, false, true);
            Assert.IsFalse(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1 = new Permission(true, true, false, true);
            Assert.IsTrue(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1 = new Permission(false, false, true, true);
            Assert.IsFalse(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1 = new Permission(true, false, true, true);
            Assert.IsTrue(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1 = new Permission(false, true, true, true);
            Assert.IsFalse(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1 = new Permission(true, true, true, true);
            Assert.IsTrue(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1.Read = false;
            Assert.IsFalse(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1.Write = false;
            Assert.IsFalse(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsTrue(p1.Delete);

            p1.Execute = false;
            Assert.IsFalse(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsTrue(p1.Delete); 
            
            p1.Delete = false;
            Assert.IsFalse(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsFalse(p1.Delete);

            p1.Read = true;
            Assert.IsTrue(p1.Read);
            Assert.IsFalse(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsFalse(p1.Delete);
            p1.Write = true;
            Assert.IsTrue(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsFalse(p1.Execute);
            Assert.IsFalse(p1.Delete);
            p1.Execute = true;
            Assert.IsTrue(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsFalse(p1.Delete);
            p1.Delete = true;
            Assert.IsTrue(p1.Read);
            Assert.IsTrue(p1.Write);
            Assert.IsTrue(p1.Execute);
            Assert.IsTrue(p1.Delete);
        }
        
        /// <summary>
        /// tests the basic permutations of protection
        /// </summary>
        [TestMethod]
        public void TestProtections()
        {
            Permission s, o, g, w;
            s = new Permission(true, true, true, true);
            o = new Permission(true, true, true, true);
            g = new Permission(true, true, true, true);
            w = new Permission(true, true, true, true);

            Protection protection ;
            protection = new Protection(s, o, g, w);

            Assert.IsTrue(protection.system.Read);
            Assert.IsTrue(protection.system.Write);
            Assert.IsTrue(protection.system.Execute);
            Assert.IsTrue(protection.system.Delete);
            Assert.IsTrue(protection.owner.Read);
            Assert.IsTrue(protection.owner.Write);
            Assert.IsTrue(protection.owner.Execute);
            Assert.IsTrue(protection.owner.Delete);
            Assert.IsTrue(protection.group.Read);
            Assert.IsTrue(protection.group.Write);
            Assert.IsTrue(protection.group.Execute);
            Assert.IsTrue(protection.group.Delete);
            Assert.IsTrue(protection.world.Read);
            Assert.IsTrue(protection.world.Write);
            Assert.IsTrue(protection.world.Execute);
            Assert.IsTrue(protection.world.Delete);

            
            protection.system.Read = true;
            protection.system.Write = false;
            protection.system.Execute = false;
            protection.system.Delete = false;
            Assert.IsTrue(protection.system.Read);
            Assert.IsFalse(protection.system.Write);
            Assert.IsFalse(protection.system.Execute);
            Assert.IsFalse(protection.system.Delete);

            protection.system.Read = false;
            protection.system.Write = true;
            protection.system.Execute = false;
            protection.system.Delete = false;
            Assert.IsFalse(protection.system.Read);
            Assert.IsTrue(protection.system.Write);
            Assert.IsFalse(protection.system.Execute);
            Assert.IsFalse(protection.system.Delete);

            protection.system.Read = true;
            protection.system.Write = true;
            protection.system.Execute = false;
            protection.system.Delete = false;
            Assert.IsTrue(protection.system.Read);
            Assert.IsTrue(protection.system.Write);
            Assert.IsFalse(protection.system.Execute);
            Assert.IsFalse(protection.system.Delete);

            protection.system.Read = false;
            protection.system.Write = false;
            protection.system.Execute = true;
            protection.system.Delete = false;
            Assert.IsFalse(protection.system.Read);
            Assert.IsFalse(protection.system.Write);
            Assert.IsTrue(protection.system.Execute);
            Assert.IsFalse(protection.system.Delete);

            protection.system.Read = true;
            protection.system.Write = false;
            protection.system.Execute = true;
            protection.system.Delete = false;
            Assert.IsTrue(protection.system.Read);
            Assert.IsFalse(protection.system.Write);
            Assert.IsTrue(protection.system.Execute);
            Assert.IsFalse(protection.system.Delete);

            protection.system.Read = false;
            protection.system.Write = true;
            protection.system.Execute = true;
            protection.system.Delete = false;
            Assert.IsFalse(protection.system.Read);
            Assert.IsTrue(protection.system.Write);
            Assert.IsTrue(protection.system.Execute);
            Assert.IsFalse(protection.system.Delete);

            protection.system.Read = true;
            protection.system.Write = true;
            protection.system.Execute = true;
            protection.system.Delete = false;
            Assert.IsTrue(protection.system.Read);
            Assert.IsTrue(protection.system.Write);
            Assert.IsTrue(protection.system.Execute);
            Assert.IsFalse(protection.system.Delete);

            protection.system.Read = false;
            protection.system.Write = false;
            protection.system.Execute = false;
            protection.system.Delete = true;
            Assert.IsFalse(protection.system.Read);
            Assert.IsFalse(protection.system.Write);
            Assert.IsFalse(protection.system.Execute);
            Assert.IsTrue(protection.system.Delete);

            protection.system.Read = true;
            protection.system.Write = false;
            protection.system.Execute = false;
            protection.system.Delete = true;
            Assert.IsTrue(protection.system.Read);
            Assert.IsFalse(protection.system.Write);
            Assert.IsFalse(protection.system.Execute);
            Assert.IsTrue(protection.system.Delete);

            protection.system.Read = false;
            protection.system.Write = true;
            protection.system.Execute = false;
            protection.system.Delete = true;
            Assert.IsFalse(protection.system.Read);
            Assert.IsTrue(protection.system.Write);
            Assert.IsFalse(protection.system.Execute);
            Assert.IsTrue(protection.system.Delete);

            protection.system.Read = true;
            protection.system.Write = true;
            protection.system.Execute = false;
            protection.system.Delete = true;
            Assert.IsTrue(protection.system.Read);
            Assert.IsTrue(protection.system.Write);
            Assert.IsFalse(protection.system.Execute);
            Assert.IsTrue(protection.system.Delete);

            protection.system.Read = false;
            protection.system.Write = false;
            protection.system.Execute = true;
            protection.system.Delete = true;
            Assert.IsFalse(protection.system.Read);
            Assert.IsFalse(protection.system.Write);
            Assert.IsTrue(protection.system.Execute);
            Assert.IsTrue(protection.system.Delete);

            protection.system.Read = true;
            protection.system.Write = false;
            protection.system.Execute = true;
            protection.system.Delete = true;
            Assert.IsTrue(protection.system.Read);
            Assert.IsFalse(protection.system.Write);
            Assert.IsTrue(protection.system.Execute);
            Assert.IsTrue(protection.system.Delete);

            protection.system.Read = false;
            protection.system.Write = true;
            protection.system.Execute = true;
            protection.system.Delete = true;
            Assert.IsFalse(protection.system.Read);
            Assert.IsTrue(protection.system.Write);
            Assert.IsTrue(protection.system.Execute);
            Assert.IsTrue(protection.system.Delete);

            protection.system.Read = true;
            protection.system.Write = true;
            protection.system.Execute = true;
            protection.system.Delete = true;
            Assert.IsTrue(protection.system.Read);
            Assert.IsTrue(protection.system.Write);
            Assert.IsTrue(protection.system.Execute);
            Assert.IsTrue(protection.system.Delete);

            protection.owner.Read = true;
            protection.owner.Write = false;
            protection.owner.Execute = false;
            protection.owner.Delete = false;
            Assert.IsTrue(protection.owner.Read);
            Assert.IsFalse(protection.owner.Write);
            Assert.IsFalse(protection.owner.Execute);
            Assert.IsFalse(protection.owner.Delete);

            protection.owner.Read = false;
            protection.owner.Write = true;
            protection.owner.Execute = false;
            protection.owner.Delete = false;
            Assert.IsFalse(protection.owner.Read);
            Assert.IsTrue(protection.owner.Write);
            Assert.IsFalse(protection.owner.Execute);
            Assert.IsFalse(protection.owner.Delete);

            protection.owner.Read = true;
            protection.owner.Write = true;
            protection.owner.Execute = false;
            protection.owner.Delete = false;
            Assert.IsTrue(protection.owner.Read);
            Assert.IsTrue(protection.owner.Write);
            Assert.IsFalse(protection.owner.Execute);
            Assert.IsFalse(protection.owner.Delete);

            protection.owner.Read = false;
            protection.owner.Write = false;
            protection.owner.Execute = true;
            protection.owner.Delete = false;
            Assert.IsFalse(protection.owner.Read);
            Assert.IsFalse(protection.owner.Write);
            Assert.IsTrue(protection.owner.Execute);
            Assert.IsFalse(protection.owner.Delete);

            protection.owner.Read = true;
            protection.owner.Write = false;
            protection.owner.Execute = true;
            protection.owner.Delete = false;
            Assert.IsTrue(protection.owner.Read);
            Assert.IsFalse(protection.owner.Write);
            Assert.IsTrue(protection.owner.Execute);
            Assert.IsFalse(protection.owner.Delete);

            protection.owner.Read = false;
            protection.owner.Write = true;
            protection.owner.Execute = true;
            protection.owner.Delete = false;
            Assert.IsFalse(protection.owner.Read);
            Assert.IsTrue(protection.owner.Write);
            Assert.IsTrue(protection.owner.Execute);
            Assert.IsFalse(protection.owner.Delete);

            protection.owner.Read = true;
            protection.owner.Write = true;
            protection.owner.Execute = true;
            protection.owner.Delete = false;
            Assert.IsTrue(protection.owner.Read);
            Assert.IsTrue(protection.owner.Write);
            Assert.IsTrue(protection.owner.Execute);
            Assert.IsFalse(protection.owner.Delete);

            protection.owner.Read = false;
            protection.owner.Write = false;
            protection.owner.Execute = false;
            protection.owner.Delete = true;
            Assert.IsFalse(protection.owner.Read);
            Assert.IsFalse(protection.owner.Write);
            Assert.IsFalse(protection.owner.Execute);
            Assert.IsTrue(protection.owner.Delete);

            protection.owner.Read = true;
            protection.owner.Write = false;
            protection.owner.Execute = false;
            protection.owner.Delete = true;
            Assert.IsTrue(protection.owner.Read);
            Assert.IsFalse(protection.owner.Write);
            Assert.IsFalse(protection.owner.Execute);
            Assert.IsTrue(protection.owner.Delete);

            protection.owner.Read = false;
            protection.owner.Write = true;
            protection.owner.Execute = false;
            protection.owner.Delete = true;
            Assert.IsFalse(protection.owner.Read);
            Assert.IsTrue(protection.owner.Write);
            Assert.IsFalse(protection.owner.Execute);
            Assert.IsTrue(protection.owner.Delete);

            protection.owner.Read = true;
            protection.owner.Write = true;
            protection.owner.Execute = false;
            protection.owner.Delete = true;
            Assert.IsTrue(protection.owner.Read);
            Assert.IsTrue(protection.owner.Write);
            Assert.IsFalse(protection.owner.Execute);
            Assert.IsTrue(protection.owner.Delete);

            protection.owner.Read = false;
            protection.owner.Write = false;
            protection.owner.Execute = true;
            protection.owner.Delete = true;
            Assert.IsFalse(protection.owner.Read);
            Assert.IsFalse(protection.owner.Write);
            Assert.IsTrue(protection.owner.Execute);
            Assert.IsTrue(protection.owner.Delete);

            protection.owner.Read = true;
            protection.owner.Write = false;
            protection.owner.Execute = true;
            protection.owner.Delete = true;
            Assert.IsTrue(protection.owner.Read);
            Assert.IsFalse(protection.owner.Write);
            Assert.IsTrue(protection.owner.Execute);
            Assert.IsTrue(protection.owner.Delete);

            protection.owner.Read = false;
            protection.owner.Write = true;
            protection.owner.Execute = true;
            protection.owner.Delete = true;
            Assert.IsFalse(protection.owner.Read);
            Assert.IsTrue(protection.owner.Write);
            Assert.IsTrue(protection.owner.Execute);
            Assert.IsTrue(protection.owner.Delete);

            protection.owner.Read = true;
            protection.owner.Write = true;
            protection.owner.Execute = true;
            protection.owner.Delete = true;
            Assert.IsTrue(protection.owner.Read);
            Assert.IsTrue(protection.owner.Write);
            Assert.IsTrue(protection.owner.Execute);
            Assert.IsTrue(protection.owner.Delete);

            protection.group.Read = true;
            protection.group.Write = false;
            protection.group.Execute = false;
            protection.group.Delete = false;
            Assert.IsTrue(protection.group.Read);
            Assert.IsFalse(protection.group.Write);
            Assert.IsFalse(protection.group.Execute);
            Assert.IsFalse(protection.group.Delete);

            protection.group.Read = false;
            protection.group.Write = true;
            protection.group.Execute = false;
            protection.group.Delete = false;
            Assert.IsFalse(protection.group.Read);
            Assert.IsTrue(protection.group.Write);
            Assert.IsFalse(protection.group.Execute);
            Assert.IsFalse(protection.group.Delete);

            protection.group.Read = true;
            protection.group.Write = true;
            protection.group.Execute = false;
            protection.group.Delete = false;
            Assert.IsTrue(protection.group.Read);
            Assert.IsTrue(protection.group.Write);
            Assert.IsFalse(protection.group.Execute);
            Assert.IsFalse(protection.group.Delete);

            protection.group.Read = false;
            protection.group.Write = false;
            protection.group.Execute = true;
            protection.group.Delete = false;
            Assert.IsFalse(protection.group.Read);
            Assert.IsFalse(protection.group.Write);
            Assert.IsTrue(protection.group.Execute);
            Assert.IsFalse(protection.group.Delete);

            protection.group.Read = true;
            protection.group.Write = false;
            protection.group.Execute = true;
            protection.group.Delete = false;
            Assert.IsTrue(protection.group.Read);
            Assert.IsFalse(protection.group.Write);
            Assert.IsTrue(protection.group.Execute);
            Assert.IsFalse(protection.group.Delete);

            protection.group.Read = false;
            protection.group.Write = true;
            protection.group.Execute = true;
            protection.group.Delete = false;
            Assert.IsFalse(protection.group.Read);
            Assert.IsTrue(protection.group.Write);
            Assert.IsTrue(protection.group.Execute);
            Assert.IsFalse(protection.group.Delete);

            protection.group.Read = true;
            protection.group.Write = true;
            protection.group.Execute = true;
            protection.group.Delete = false;
            Assert.IsTrue(protection.group.Read);
            Assert.IsTrue(protection.group.Write);
            Assert.IsTrue(protection.group.Execute);
            Assert.IsFalse(protection.group.Delete);

            protection.group.Read = false;
            protection.group.Write = false;
            protection.group.Execute = false;
            protection.group.Delete = true;
            Assert.IsFalse(protection.group.Read);
            Assert.IsFalse(protection.group.Write);
            Assert.IsFalse(protection.group.Execute);
            Assert.IsTrue(protection.group.Delete);

            protection.group.Read = true;
            protection.group.Write = false;
            protection.group.Execute = false;
            protection.group.Delete = true;
            Assert.IsTrue(protection.group.Read);
            Assert.IsFalse(protection.group.Write);
            Assert.IsFalse(protection.group.Execute);
            Assert.IsTrue(protection.group.Delete);

            protection.group.Read = false;
            protection.group.Write = true;
            protection.group.Execute = false;
            protection.group.Delete = true;
            Assert.IsFalse(protection.group.Read);
            Assert.IsTrue(protection.group.Write);
            Assert.IsFalse(protection.group.Execute);
            Assert.IsTrue(protection.group.Delete);

            protection.group.Read = true;
            protection.group.Write = true;
            protection.group.Execute = false;
            protection.group.Delete = true;
            Assert.IsTrue(protection.group.Read);
            Assert.IsTrue(protection.group.Write);
            Assert.IsFalse(protection.group.Execute);
            Assert.IsTrue(protection.group.Delete);

            protection.group.Read = false;
            protection.group.Write = false;
            protection.group.Execute = true;
            protection.group.Delete = true;
            Assert.IsFalse(protection.group.Read);
            Assert.IsFalse(protection.group.Write);
            Assert.IsTrue(protection.group.Execute);
            Assert.IsTrue(protection.group.Delete);

            protection.group.Read = true;
            protection.group.Write = false;
            protection.group.Execute = true;
            protection.group.Delete = true;
            Assert.IsTrue(protection.group.Read);
            Assert.IsFalse(protection.group.Write);
            Assert.IsTrue(protection.group.Execute);
            Assert.IsTrue(protection.group.Delete);

            protection.group.Read = false;
            protection.group.Write = true;
            protection.group.Execute = true;
            protection.group.Delete = true;
            Assert.IsFalse(protection.group.Read);
            Assert.IsTrue(protection.group.Write);
            Assert.IsTrue(protection.group.Execute);
            Assert.IsTrue(protection.group.Delete);

            protection.group.Read = true;
            protection.group.Write = true;
            protection.group.Execute = true;
            protection.group.Delete = true;
            Assert.IsTrue(protection.group.Read);
            Assert.IsTrue(protection.group.Write);
            Assert.IsTrue(protection.group.Execute);
            Assert.IsTrue(protection.group.Delete);

            protection.world.Read = true;
            protection.world.Write = false;
            protection.world.Execute = false;
            protection.world.Delete = false;
            Assert.IsTrue(protection.world.Read);
            Assert.IsFalse(protection.world.Write);
            Assert.IsFalse(protection.world.Execute);
            Assert.IsFalse(protection.world.Delete);

            protection.world.Read = false;
            protection.world.Write = true;
            protection.world.Execute = false;
            protection.world.Delete = false;
            Assert.IsFalse(protection.world.Read);
            Assert.IsTrue(protection.world.Write);
            Assert.IsFalse(protection.world.Execute);
            Assert.IsFalse(protection.world.Delete);

            protection.world.Read = true;
            protection.world.Write = true;
            protection.world.Execute = false;
            protection.world.Delete = false;
            Assert.IsTrue(protection.world.Read);
            Assert.IsTrue(protection.world.Write);
            Assert.IsFalse(protection.world.Execute);
            Assert.IsFalse(protection.world.Delete);

            protection.world.Read = false;
            protection.world.Write = false;
            protection.world.Execute = true;
            protection.world.Delete = false;
            Assert.IsFalse(protection.world.Read);
            Assert.IsFalse(protection.world.Write);
            Assert.IsTrue(protection.world.Execute);
            Assert.IsFalse(protection.world.Delete);

            protection.world.Read = true;
            protection.world.Write = false;
            protection.world.Execute = true;
            protection.world.Delete = false;
            Assert.IsTrue(protection.world.Read);
            Assert.IsFalse(protection.world.Write);
            Assert.IsTrue(protection.world.Execute);
            Assert.IsFalse(protection.world.Delete);

            protection.world.Read = false;
            protection.world.Write = true;
            protection.world.Execute = true;
            protection.world.Delete = false;
            Assert.IsFalse(protection.world.Read);
            Assert.IsTrue(protection.world.Write);
            Assert.IsTrue(protection.world.Execute);
            Assert.IsFalse(protection.world.Delete);

            protection.world.Read = true;
            protection.world.Write = true;
            protection.world.Execute = true;
            protection.world.Delete = false;
            Assert.IsTrue(protection.world.Read);
            Assert.IsTrue(protection.world.Write);
            Assert.IsTrue(protection.world.Execute);
            Assert.IsFalse(protection.world.Delete);

            protection.world.Read = false;
            protection.world.Write = false;
            protection.world.Execute = false;
            protection.world.Delete = true;
            Assert.IsFalse(protection.world.Read);
            Assert.IsFalse(protection.world.Write);
            Assert.IsFalse(protection.world.Execute);
            Assert.IsTrue(protection.world.Delete);

            protection.world.Read = true;
            protection.world.Write = false;
            protection.world.Execute = false;
            protection.world.Delete = true;
            Assert.IsTrue(protection.world.Read);
            Assert.IsFalse(protection.world.Write);
            Assert.IsFalse(protection.world.Execute);
            Assert.IsTrue(protection.world.Delete);

            protection.world.Read = false;
            protection.world.Write = true;
            protection.world.Execute = false;
            protection.world.Delete = true;
            Assert.IsFalse(protection.world.Read);
            Assert.IsTrue(protection.world.Write);
            Assert.IsFalse(protection.world.Execute);
            Assert.IsTrue(protection.world.Delete);

            protection.world.Read = true;
            protection.world.Write = true;
            protection.world.Execute = false;
            protection.world.Delete = true;
            Assert.IsTrue(protection.world.Read);
            Assert.IsTrue(protection.world.Write);
            Assert.IsFalse(protection.world.Execute);
            Assert.IsTrue(protection.world.Delete);

            protection.world.Read = false;
            protection.world.Write = false;
            protection.world.Execute = true;
            protection.world.Delete = true;
            Assert.IsFalse(protection.world.Read);
            Assert.IsFalse(protection.world.Write);
            Assert.IsTrue(protection.world.Execute);
            Assert.IsTrue(protection.world.Delete);

            protection.world.Read = true;
            protection.world.Write = false;
            protection.world.Execute = true;
            protection.world.Delete = true;
            Assert.IsTrue(protection.world.Read);
            Assert.IsFalse(protection.world.Write);
            Assert.IsTrue(protection.world.Execute);
            Assert.IsTrue(protection.world.Delete);

            protection.world.Read = false;
            protection.world.Write = true;
            protection.world.Execute = true;
            protection.world.Delete = true;
            Assert.IsFalse(protection.world.Read);
            Assert.IsTrue(protection.world.Write);
            Assert.IsTrue(protection.world.Execute);
            Assert.IsTrue(protection.world.Delete);

            protection.world.Read = true;
            protection.world.Write = true;
            protection.world.Execute = true;
            protection.world.Delete = true;
            Assert.IsTrue(protection.world.Read);
            Assert.IsTrue(protection.world.Write);
            Assert.IsTrue(protection.world.Execute);
            Assert.IsTrue(protection.world.Delete);

        }
    }
}
