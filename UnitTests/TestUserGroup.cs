using System;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    internal class TestUserGroup : ISecurityGroup
    {
        public Guid Id { get; set; }

        public TestUserGroup(Guid p)
        {
            this.Id = p;
        }
    }
}