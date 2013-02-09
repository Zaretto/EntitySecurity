using System;

namespace ReferenceMonitorTests
{
    internal class TestUser
    {
        public TestUser(Guid id)
        {
            this.Id = id;
        }

        public Guid Id { get; set; }
    }
}