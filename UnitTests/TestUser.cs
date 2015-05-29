using System;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    internal class TestUser : ISecurityGroup
    {
        public TestUser(Guid id)
        {
            this.Id = id;
        }

        public Guid Id { get; set; }
    }
}