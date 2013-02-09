using System;

namespace ReferenceMonitorTests
{
    internal class TestGroup
    {
        public Guid Id { get; set; }

        public TestGroup(Guid p)
        {
            this.Id = p;
        }
    }
}