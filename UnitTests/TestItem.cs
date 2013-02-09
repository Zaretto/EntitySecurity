using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    class TestItem : IControlledObject
    {
        public TestItem(User User, IGroup Group, Protection Protection)
        {
            this.owner = User;
            this.group = Group;
            this.protection = Protection;
        }

        public User owner { get; set; }

        public Protection protection { get; set; }

        public IGroup group { get; set; }

        public Zaretto.Security.IGroup GetGroup()
        {
            return group;
        }

        public Zaretto.Security.IUser GetOwner()
        {
            return owner;
        }

        public Zaretto.Security.Protection GetProtection()
        {
            return protection;
        }

    }
}
