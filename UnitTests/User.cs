using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    class User : ISubject, IUser
    {
        private TestGroup group;
        private TestUser user;

        public User(int p1, int p2)
        {
            user = new TestUser(p1);
            group = new TestGroup(p2);
            Privileges = new List<Privilege>();
        }

        public int GetId()
        {
            return user.Id;
        }

        public IGroup GetGroup()
        {
            return group;
        }

        public IEnumerable<Privilege> GetPrivileges()
        {
            return Privileges;
        }

        public bool IsOwnerEquivalent(IControlledObject obj)
        {
            return obj.GetOwner().GetId() == user.Id;
        }

        public List<Privilege> Privileges { get; set; }
    }
}
