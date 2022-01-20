using System;
using Zaretto.Security;

namespace TestObjects
{
    public class TestGroup : IControlledObjectGroup
    {
        public Guid Id { get; set; }

        public TestGroup(Guid p, IControlledObjectOperation applicableOperation)
        {
            this.Id = p;
            ApplicableOperation = applicableOperation;
        }


        public IControlledObjectOperation ApplicableOperation {get;set;}
    }
}