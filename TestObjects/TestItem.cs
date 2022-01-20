using System;
using System.Collections.Generic;
using Zaretto.Security;
using System.Linq;
namespace TestObjects
{
    public class TestItem : IControlledObject
    {
        public TestItem(User User, TestGroup readGroup, TestGroup writeGroup, IProtection Protection)
        {
            this.owner = User;
            _groups.Add(readGroup);
            _groups.Add(writeGroup);
            this.protection = Protection;
        }

        public User owner { get; set; }

        public IProtection protection { get; set; }

        public Zaretto.Security.IProtection Protection
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

        public string SimpleId
        {
            get {
            return "SimplieId";
            }
        }

        public string OwnerDescription
        {
            get
            {
                return owner.Id.ToString();
            }
        }
        public List<TestGroup> readGroups = new List<TestGroup>();
        public List<IControlledObjectGroup> _groups = new List<IControlledObjectGroup>();

        public List<IControlledObjectGroup> Groups
        {
           get{return _groups;}
        }
    }
}