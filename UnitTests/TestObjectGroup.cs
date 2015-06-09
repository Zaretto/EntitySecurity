using System;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    internal class TestGroup : IControlledObjectGroup
    {
        public Guid Id { get; set; }

        public TestGroup(Guid p, Operation applicableOperation)
        {
            this.Id = p;
            ApplicableOperation = applicableOperation;
        }


        public Operation ApplicableOperation {get;set;}
    }
}