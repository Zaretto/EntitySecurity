using System;
using Zaretto.Security;

namespace TestObjects
{
    public class TestUserGroup : ISecurityGroup
    {
        public Guid Id { get; set; }

        public TestUserGroup(Guid p)
        {
            this.Id = p;
        }
    }
}