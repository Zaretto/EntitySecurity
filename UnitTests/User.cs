using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    class User : ISubject
    {
        int PrivilegeMask = 0;
        //private List<Privilege> Privileges { get; set; }

        private TestGroup group;
        private TestUser user;

        public Guid Id { get { return user.Id; } }

        public User(Guid p1, Guid p2)
        {
            user = new TestUser(p1);
            group = new TestGroup(p2);
            PrivilegeMask = 0;
//            Privileges = new List<Privilege>();
        }

        public bool IsOwnerEquivalent(IControlledObject obj)
        {
            return obj.UserId == user.Id;
        }
        
        public void AddPrivilege(Privilege p)
        {
            PrivilegeMask |= (int)p;
            //Privileges.Add(p);
        }

        public void RemovePrivilege(Privilege p)
        {
            PrivilegeMask &= ~(int)p;
//            Privileges.Remove(p);
        }

        public bool IsGroupEquivalent(IControlledObject obj)
        {
            return obj.GroupId == group.Id;
        }

        public bool HasPrivilege(Privilege p)
        {
            return (PrivilegeMask & (int)p) == (int)p;
        }
    }
}
