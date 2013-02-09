using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    class User : ISubject
    {
        private TestGroup group;
        private TestUser user;

        public User(Guid p1, Guid p2)
        {
            user = new TestUser(p1);
            group = new TestGroup(p2);
            Privileges = new List<Privilege>();
        }

        public Guid Id { get { return user.Id; } }
        public IEnumerable<Privilege> GetPrivileges()
        {
            return Privileges;
        }

        public bool IsOwnerEquivalent(IControlledObject obj)
        {
            return obj.UserId == user.Id;
        }

        public List<Privilege> Privileges { get; set; }


        public bool IsGroupEquivalent(IControlledObject obj)
        {
            return obj.GroupId == group.Id;
        }

        public bool HasPrivilege(Privilege p)
        {
            return Privileges.Contains(p);
        }
    }
}
