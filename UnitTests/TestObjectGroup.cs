using System;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    internal class TestGroup : IControlledObjectGroup
    {
        public Guid Id { get; set; }

        public TestGroup(Guid p, Permission applicableTo)
        {
            this.Id = p;
            ApplicableTo = applicableTo;
        }

        public Permission ApplicableTo {get;set;}
    }
}