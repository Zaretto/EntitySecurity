using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    class TestGroup : IGroup
    {
        public int Id;

        public TestGroup(int p) 
        {
            this.Id = p;
        }

        public int GetId()
        {
            return Id;
        }
    }
}
