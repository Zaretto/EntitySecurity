using System;
namespace Zaretto.Security
{
    /// <summary>
    /// Defines the protection applied to an IControlledObject. This consists of a set of 4 permissions for
    /// System, Owner, Group, World and is usually persisted in an integer.
    /// </summary>
    [Serializable]
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

        /// Combined 16bit permission;
        /// 0xFFFF
        ///   |||+World - bits LSB to NSB: RWED
        ///   ||+ Group
        ///   |+Owner RWED
        ///   | System RWED
        ///   
        /// Bit:
        /// 0: World Read
        /// 1: World Write
        /// 2: World Execute
        /// 3: World Delete

        /// 4: Group Read
        /// 5: Group Write
        /// 6: Group Execute
        /// 7: Group Delete
        /// 
        /// 8: Owner Read
        /// 9: Owner Write
        /// 10: Owner Execute
        /// 11: Owner Delete
        /// 
        /// 12: System Read
        /// 13: System Write
        /// 14: System Execute
        /// 16: System Delete
        /// 
        /// 0xSO
        /// 
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

        public override string ToString()
        {
            return "S:" + system
                    + " O:" + owner
                    + " G:" + group
                    + " W:" + world;
        }
    }
}