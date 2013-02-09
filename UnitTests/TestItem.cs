using System;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    internal class TestItem : IControlledObject
    {
        public TestItem(User User, TestGroup Group, Protection Protection)
        {
            this.owner = User;
            this.group = Group;
            this.protection = Protection;
        }

        public User owner { get; set; }

        public TestGroup group { get; set; }

        public Protection protection { get; set; }

        public Zaretto.Security.Protection Protection
        {
            get { return protection; }
        }

        public Guid UserId
        {
            get
            {
                return owner.Id;
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public Guid GroupId
        {
            get
            {
                return group.Id;
            }
            set
            {
                throw new NotImplementedException();
            }
        }
    }
}