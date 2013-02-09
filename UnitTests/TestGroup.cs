using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    class TestGroup 
    {
        public Guid Id { get; set; }

        public TestGroup(Guid p) 
        {
            this.Id = p;
        }
    }
}
