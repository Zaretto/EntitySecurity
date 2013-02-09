namespace Zaretto.Security
{
    public class Protection
    {
        public const int Standard = 0x3F00; //S:RW O:RWED G: W:

        /**
         * Construct either using a combined (4 char format SOGW eg. 7751 =S:RWED, O:RWED, G:R E, O:R   )
         * or by specifying as individual values;
         */

        public Protection(Permission system, Permission owner, Permission group, Permission world)
        {
            this.system = new Permission(system);
            this.owner = new Permission(owner);
            this.group = new Permission(group);
            this.world = new Permission(world);
        }

        /// <summary>
        /// construct using 4 bit masks, e.g. Permission.REWD
        /// /// </summary>
        /// <param name="system"></param>
        /// <param name="owner"></param>
        /// <param name="group"></param>
        /// <param name="world"></param>
        public Protection(byte system, byte owner, byte group, byte world)
        {
            this.system = new Permission(system);
            this.owner = new Permission(owner);
            this.group = new Permission(group);
            this.world = new Permission(world);
        }

        /// <summary>
        /// create a protection based on combined (32 bit value)
        /// S : 0xf
        /// O : 0xf0
        /// G : 0xf00
        /// W : 0xf000
        /// </summary>
        /// <param name="combined"></param>
        public Protection(int combined)
        {
            Combined = combined;
        }

        public Permission system { get; set; }

        public Permission owner { get; set; }

        public Permission group { get; set; }

        public Permission world { get; set; }

        public int Combined
        {
            get
            {
                return (system.Combined << 12) | (owner.Combined << 8) | (group.Combined << 4) | (world.Combined << 0);
            }
            set
            {
                world = new Permission(value & 0xF);
                group = new Permission((value & 0xF0) >> 4);
                owner = new Permission((value & 0xF00) >> 8);
                system = new Permission((value & 0xF000) >> 12);
            }
        }

        //private Permission _system = new Permission(0);
        //private Permission _owner = new Permission(0);
        //private Permission _group = new Permission(0);
        //private Permission _world = new Permission(0);

        //public Permission system
        //{
        //    get
        //    {
        //        _system.Combined = (byte)((Combined & 0xF000) >> 12);
        //        return _system;
        //        //return new Permission((Combined & 0xF000) >> 12);
        //    }
        //    set
        //    {
        //        Combined = (Combined & 0xfff) | value.Combined << 12;
        //    }
        //}
        //public Permission owner
        //{
        //    get
        //    {
        //        _owner.Combined = (byte)((Combined & 0xF00) >> 8);
        //        return _owner;
        //    }
        //    set
        //    {
        //        Combined = (Combined & 0xf0ff) | value.Combined << 8;
        //    }
        //}
        //public Permission group
        //{
        //    get
        //    {
        //        _group.Combined = (byte)((Combined & 0xF0) >> 4);
        //        return _group;
        //    }
        //    set
        //    {
        //        Combined = (Combined & 0xff0f) | value.Combined << 4;
        //    }
        //}
        //public Permission world
        //{
        //    get
        //    {
        //        _world.Combined = (byte)((Combined & 0xF) >> 0);
        //        return _world;
        //    }
        //    set
        //    {
        //        Combined = (Combined & 0xfff0) | value.Combined << 0;
        //    }
        //}

        //private int Combined;
        //{
        //    get
        //    {
        //        return (system.Combined << 12) | (owner.Combined << 8) | (group.Combined << 4) | (world.Combined << 0);
        //    }
        //    set
        //    {
        //        world = new Permission(value & 0xF);
        //        group = new Permission((value & 0xF0) >> 4);
        //        owner = new Permission((value & 0xF00) >> 8);
        //        system = new Permission((value & 0xF000) >> 12);
        //    }
        //}
        public override string ToString()
        {
            return "S:" + system
                    + " O:" + owner
                    + " G:" + group
                    + " W:" + world;
        }
    }
}