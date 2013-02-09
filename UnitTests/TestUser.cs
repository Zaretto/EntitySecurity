using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    class TestUser : IUser
    {
        public TestUser(int id)
        {
            this.Id = id;
        }
        
        public int GetId()
        {
            return Id;
        }

        public int Id { get; set; }
    }
}
