using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    class TestUser 
    {
        public TestUser(Guid id)
        {
            this.Id = id;
        }
        
        public Guid Id { get; set; }
    }
}
