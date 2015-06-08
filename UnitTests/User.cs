using System;
using System.Linq;
using System.Collections.Generic;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    internal class User : ISubject
    {
        private int PrivilegeMask = 0;

        //private List<Privilege> Privileges { get; set; }

        private List<ISecurityGroup> Groups = new List<ISecurityGroup>();
        private TestUser user;
        private ReferenceMonitor ReferenceMonitor = new ReferenceMonitor();

        public Guid Id { get { return user.Id; } }

        public User(Guid p1, ISecurityGroup readGroup, ISecurityGroup writeGroup = null)
        {
            user = new TestUser(p1);
            Groups.Add(readGroup);
            if (writeGroup != null) 
                Groups.Add(writeGroup);
            PrivilegeMask = 0;

            //            Privileges = new List<Privilege>();
        }

        public bool IsOwnerEquivalent(Operation operation, IControlledObject obj)
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

        public bool IsGroupEquivalent(Operation operation, IControlledObject obj)
        {
            return obj.Groups.Where(og => Groups.Any(xx => xx.Id == og.Id))
                .Any(og => ReferenceMonitor.HasPermissionRequiredForOperation(operation, og.ApplicableTo));
        }

        public bool HasPrivilege(Privilege p)
        {
            return (PrivilegeMask & (int)p) == (int)p;
        }


        public string Identity
        {
            get { return this.Id.ToString(); }
        }
    }
}