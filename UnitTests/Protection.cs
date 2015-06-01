using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zaretto.Security;

namespace ReferenceMonitorTests
{
    /// <summary>
    /// Defines the protection applied to an IControlledObject. This consists of a set of 4 permissions for
    /// System, Owner, Group, World and is usually persisted in an integer.
    /// </summary>
    [Serializable]
    public class Protection : IProtection
    {
        public const int Standard = 0x3F00; //S:RW O:RWED G: W:

        /**
         * Construct either using a combined (4 char format SOGW eg. 7751 =S:RWED, O:RWED, G:R E, O:R   )
         * or by specifying as individual values;
         */

        public Protection(Permission system, Permission owner, Permission group, Permission world)
        {
            this._system = new Permission(system);
            this._owner = new Permission(owner);
            this._group = new Permission(group);
            this._world = new Permission(world);
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
            this._system = new Permission(system);
            this._owner = new Permission(owner);
            this._group = new Permission(group);
            this._world = new Permission(world);
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

        Permission _system;

        Permission _owner;

        Permission _group;
        Permission _world;

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
                return (_system.Combined << 12) | (_owner.Combined << 8) | (_group.Combined << 4) | (_world.Combined << 0);
            }
            set
            {
                _world = new Permission(value & 0xF);
                _group = new Permission((value & 0xF0) >> 4);
                _owner = new Permission((value & 0xF00) >> 8);
                _system = new Permission((value & 0xF000) >> 12);
            }
        }

        public override string ToString()
        {
            return "S:" + _system
                    + " O:" + _owner
                    + " G:" + _group
                    + " W:" + _world;
        }


        public IPermission system
        {
            get
            {
                return _system;
            }
            set
            {
                _system.SetFromIPermission(value);;
            }
        }

        public IPermission owner
        {
            get
            {
                return _owner;
            }
            set
            {
                _owner.SetFromIPermission(value);;
            }
        }

        public IPermission group
        {
            get
            {
                return _group;
            }
            set
            {
                _group.SetFromIPermission(value);
            }
        }

        public IPermission world
        {
            get
            {
                return _world;
            }
            set
            {
                _world.SetFromIPermission(value);;
            }
        }
    }
}