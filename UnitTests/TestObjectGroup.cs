using System;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    internal class TestGroup : IControlledObjectGroup
    {
        public Guid Id { get; set; }

        public TestGroup(Guid p, IPermission applicableTo, Operation applicableOperation)
        {
            this.Id = p;
            ApplicableTo = applicableTo;
            ApplicableOperation = applicableOperation;
        }

        public IPermission ApplicableTo {get;set;}


        public Operation ApplicableOperation {get;set;}
    }
}