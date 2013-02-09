  /*---------------------------------------------------------------------------
   *
   *	Title                : System library -  security reference monitor
   *
   *	Filename             : ReferenceMonitor.cs
   *
   *	File Type            : Implementation File
   *
   *	Description          : The security system is be depicted in terms of
   *                         : subjects, objects, an authorization database, an audit trail.
   *                         : The reference monitor is the control center that authenticates
   *                         : subjects and implements and enforces the
   *                         : security policy for every access to an object by a subject.
   * 
   *                         : Subjects  	           Entities gain access to information on behalf of people.
   *                         : Objects                 Entities to be protected
   *                         : Authorization database  Repository for the security attributes of
   *                           subjects and objects. From these attributes, 
   *                           the reference monitor determines the  access permitted.
   * 
   *                         : Audit trail 	           Record of all security-relevant events, such as access attempts, successful or not.
   * 
   *                         : The reference monitor enforces the security policy by authorizing the
   *                         : creation of subjects, by granting subjects access to objects based on
   *                         : the information in a dynamic authorization database, and by recording
   *                         : events, as necessary, in the audit trail. 
   *
   *	Author               : Richard Harrison
   *
   *    References           : James Anderson & Co: ESD-TR-75-51, Vol.II 
   *                         : Computer Security Technology Planning Study (Oct, 1972) 
   *                         : http://csrc.nist.gov/publications/history/ande72.pdf
   *
   *                         : OpenVMS Guide to System Security : AA--Q2HLE--TE 
   *                         : http://h71000.www7.hp.com/doc/73final/6346/6346pro.html
   *
   *                         : Record interface segmentation - Object Mapping
   *                         : http://chateau-logic.com/content/record-interface-segmentation-object-mapping
   *
   *	Creation Date        : October 1999, PHP Version 20012, C# 21-JAN-2013
   *
   *	Version              : $Header: $
   *
   *  Copyright (C)1999-2013  Richard Harrison       All Rights Reserved.
   * 
   * NOTES: 
   *   1. Record control will be by record interface segmentation - where a record in the DB
   *      has extra fields that relate to the interface that the implementing object 
   *      implements, so for the controlled object this will be 
   *      - Protection INT
   *      - Owner INT
   *      - Group INT
   *   OldNote: Objects (e.g. tables, records and fields) will be controlled by having
   *   their identity in the ObjectSecurity table - which will have the following:
   *    ObjectID (table.[id].[field]) - field/id can be omitted and will match the next
   *    highest - to allow for inherited permissions
   *---------------------------------------------------------------------------*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Zaretto.Security
{
    public enum Operation
    {
        Read      = 1 << 1,
        Write     = 1 << 2,
        Update    = 1 << 3,
        Delete    = 1 << 4,
        Create    = 1 << 5,
        List      = 1 << 6,
        Security  = 1 << 7,
    };

    public enum Privilege
    {
        BYPASS      = 1 << 1,    // Bypass object protection,                      All
        DIAGNOSE    = 1 << 2,    // Diagnose objects                               Objects
        EXQUOTA     = 1 << 3,    // May exceed quotas=                             Devour
        GROUP       = 1 << 4,    // Access via group protection when not in group = 0x0000, Group
        IMPERSONATE = 1 << 5,    // Become another subject/user,                   All
        IMPORT      = 1 << 6,    // Perform import operations,                     Objects
        OPER        = 1 << 7,    // Act as system operator,                        System
        READALL     = 1 << 8,    // Read any object bypassing,                     Objects
        SECURITY    = 1 << 9,    // Perform Security Operations,                   System
        SETPRV      = 1 << 10,   // Change own privilege levels,                   All
        SYSPRV      = 1 << 11,   // Access objects via system protection,          All

    };

    public interface ISubject
    {
        /**
         * Returns an array of privileges assigned to this subject
         * @access public
         * @return array of privileges
         *   PRIV         Description                                    Level
         *   -------------------------------------------------------------------
         *   BYPASS,      Bypass object protection,                      All
         *   DIAGNOSE,    Diagnose objects,                              Objects
         *   EXQUOTA,     May exceed quotas,                             Devour
         *   GROUP,       Access via group protection when not in group, Group
         *   IMPERSONATE, Become another subject/user,                   All
         *   IMPORT,      Perform import operations,                     Objects
         *   OPER,        Act as system operator,                        System
         *   READALL,     Read any object bypassing,                     Objects
         *   SECURITY,    Perform Security Operations,                   System
         *   SETPRV,      Change own privilege levels,                   All
         *   SYSPRV,      Access objects via system protection,          All
         */
        bool HasPrivilege(Privilege p);

        void AddPrivilege(Privilege p);
        void RemovePrivilege(Privilege p);

        /// <summary>
        /// returns true if the owner of the controlled object is equivalent to this
        /// (e.g. obj.GetId() == Id)
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        bool IsOwnerEquivalent(IControlledObject obj);

        /// <summary>
        /// returns true if the owner of the controlled object is equivalent to this
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        bool IsGroupEquivalent(IControlledObject obj);
    };

    public interface IControlledObject 
    {
        /**
         * Returns the protection of this object; a Protection object
         * @access public
         * @return Int
         */
        Protection Protection {get;}

        Guid UserId { get; set; }
        Guid GroupId { get; set; }
    };

    public class Permission
    {
        public const byte Deny = 0x0;
        public const byte Full = 0xf;
        public const byte ReadOnly = 0x1;
        public const byte ReadWrite = 0x2;

        public const byte B_Read    = 0x1;
        public const byte B_Write   = 0x2;
        public const byte B_Execute = 0x4;
        public const byte B_Delete  = 0x8;

        public const byte R = B_Read;
        public const byte W = B_Write;
        public const byte E = B_Execute;
        public const byte D = B_Delete;
        public const byte RW = B_Read | B_Write;
        public const byte RWE = B_Read | B_Write | B_Execute;
        public const byte RWED = B_Read | B_Write | B_Execute | B_Delete;
        public const byte RED = B_Read | B_Execute | B_Delete;
        public const byte RE = B_Read  | B_Execute ;

        /**
         * Construct either using a combined (byte format encoding bits as RWED eg. 5=R E)
         * or by specifying as individual values;
         */
        public Permission(bool read, bool write, bool execute, bool delete)
        {
            Combined = 0;
            Read = read;
            Write = write;
            Execute = execute;
            Delete = delete;
        }
        /// <summary>
        /// construct from a combined permission.
        /// 0: Read 
        /// 2: Write
        /// 4: Execute
        /// 8: Delete
        /// </summary>
        /// <param name="combined"></param>
        public Permission(byte combined)
        {
            Read = (combined & B_Read) == B_Read;
            Write = (combined & B_Write) == B_Write;
            Execute = (combined & B_Execute) == B_Execute;
            Delete = (combined & B_Delete) == B_Delete;
        }
        public Permission(Permission from)
        {
            Read = from.Read;
            Write = from.Write;
            Execute = from.Execute;
            Delete = from.Delete;
        }
        public Permission(int combined)
        {
            Read = (combined & B_Read) == B_Read;
            Write = (combined & B_Write) == B_Write;
            Execute = (combined & B_Execute) == B_Execute;
            Delete = (combined & B_Delete) == B_Delete;
        }

        internal byte Combined;

        public bool Read
        {
            get
            {
                return (Combined & B_Read) == B_Read;
            }
            set
            {
                if (value)
                    Combined |= B_Read;
                else
                    Combined &= (byte)(~B_Read&0xff);
            }
        }
        public bool Write
        {
            get
            {
                return (Combined & B_Write) == B_Write;
            }
            set
            {
                if (value)
                    Combined |= B_Write;
                else
                    Combined &= (byte)(~B_Write & 0xff);
            }
        }
        public bool Execute
        {
            get
            {
                return (Combined & B_Execute) == B_Execute;
            }
            set
            {
                if (value)
                    Combined |= B_Execute;
                else
                    Combined &= (byte)(~B_Execute & 0xff);
            }
        }
        public bool Delete
        {
            get
            {
                return (Combined & B_Delete) == B_Delete;
            }
            set
            {
                if (value)
                    Combined |= B_Delete;
                else
                    Combined &= (byte)(~B_Delete & 0xff);
            }
        }
        //public bool Write { get { return permission[B_Write]; } set { permission[B_Write] = value; } }
        //public bool Execute { get { return permission[B_Execute]; } set { permission[B_Execute] = value; } }
        //public bool Delete { get { return permission[B_Delete]; } set { permission[B_Delete] = value; } }

            static string add_permission_to_string(bool value, string if_set)
        {
            if (value)
                return if_set;
            else
                return "";
        }

        string __toString()
        {
            return add_permission_to_string(Read, "R")
                + add_permission_to_string(Write, "W")
                + add_permission_to_string(Execute, "E")
                + add_permission_to_string(Delete, "D");
        }

    };


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
    };

    public class ReferenceMonitor
    {
        /// <summary>
        /// Given an operation get the relevant permission - mapping from operations to permissions
        /// </summary>
        /// <param name="operation"></param>
        /// <param name="permission"></param>
        /// <returns></returns>
        private static bool permitted(Operation operation, Permission permission)
        {
            switch (operation)
            {
                case Operation.Update:
                case Operation.Write:
                case Operation.Create:
                    return permission.Write;

                case Operation.Read:
                    return permission.Read;

                case Operation.Delete:
                    return permission.Delete;

                case Operation.List:
                    // only items that have execute and read can be listed. this allows fine
                    // grained control of items appearing in lists - i.e. to remove an item from a list do not grant execute - just read.
                    return permission.Execute && permission.Read;
            }
            return false;
        }

        public static bool IsPermitted(Operation operation, ISubject subject, IControlledObject obj, bool accessViaSystem = false)
        {
            //
            // if the object is null then it appears safe to grant access.
            if (obj == null)
                return true;

            var protection = obj.Protection;

            //
            // least costly - so try this first.
            if (ReferenceMonitor.permitted(operation, protection.world))
                return true;

            //
            // access via owner
            if (subject.IsOwnerEquivalent(obj) && ReferenceMonitor.permitted(operation, protection.owner))
            {
                return true;
            }

            //
            // if system user - or have System Privilege then can access through the system protection.
            // accessViaSystem allows services to access via system protection and is part of the privilege elevation
            // and impersonation.
            if ((accessViaSystem || subject.HasPrivilege(Privilege.SYSPRV)) && ReferenceMonitor.permitted(operation, protection.system))
            {
                return true;
            }

            //
            // only the owner or a subject with SECURITY priv can change permissions and protections.
            if (operation == Operation.Security)
                return subject.IsOwnerEquivalent(obj) || subject.HasPrivilege(Privilege.SECURITY);

            /*
             * if the subject has group access (priv) or the group is the same 
             * between the subj and obj then grant access based on the group protection.
             */
            if ((subject.IsGroupEquivalent(obj) || subject.HasPrivilege(Privilege.GROUP))
                && ReferenceMonitor.permitted(operation, protection.group))
                return true;

            /*
             * If the subject (user) has BYPASS then it allows access to everything in an uncontrolled (i.e. unix root)
             * type of manner, so just allow.
             */
            if (subject.HasPrivilege(Privilege.BYPASS))
                return true;

            /*
             * If the subject (user) has READALL then permit any read or list
             */
            if ((operation == Operation.Read || operation == Operation.List)
                && subject.HasPrivilege(Privilege.READALL))
            {
                return true;
            }

            return false;
        }
    }
}


