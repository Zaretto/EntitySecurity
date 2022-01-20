using System;
using Zaretto.Security;

namespace TestObjects
{
    public class TestUser : ISecurityGroup
    {
        public TestUser(Guid id)
        {
            this.Id = id;
        }

        public Guid Id { get; set; }
    }
}