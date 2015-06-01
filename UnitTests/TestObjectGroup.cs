using System;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    internal class TestGroup : IControlledObjectGroup
    {
        public Guid Id { get; set; }

        public TestGroup(Guid p, IPermission applicableTo)
        {
            this.Id = p;
            ApplicableTo = applicableTo;
        }

        public IPermission ApplicableTo {get;set;}
    }
}