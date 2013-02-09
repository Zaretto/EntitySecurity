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
    public enum Action
    {
        Read,
        Write,
        Update,
        Delete,
        Create,
        List,
        Security
    };

    public interface IUser
    {
        int GetId();
    };

    public interface IGroup 
    {
        int GetId();
    };

    public enum Privilege
    {
        BYPASS,      // Bypass object protection,                      All
        DIAGNOSE,    // Diagnose objects,                              Objects
        EXQUOTA,     // May exceed quotas,                             Devour
        GROUP,       // Access via group protection when not in group, Group
        IMPERSONATE, // Become another subject/user,                   All
        IMPORT,      // Perform import operations,                     Objects
        OPER,        // Act as system operator,                        System
        READALL,     // Read any object bypassing,                     Objects
        SECURITY,    // Perform Security Operations,                   System
        SETPRV,      // Change own privilege levels,                   All
        SYSPRV,      // Access objects via system protection,          All

    };

    public interface ISubject
    {
        /// <summary>
        /// Returns the Id of this subject
        /// </summary>
        /// <returns></returns>
        int GetId();
 
        /// <summary>
        /// Returns the group of this subject
        /// </summary>
        /// <returns>IGroup</returns>
        IGroup GetGroup();

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
        IEnumerable<Privilege> GetPrivileges();

        /// <summary>
        /// returns true if the owner of the controlled object is equivalent to this
        /// (e.g. obj.GetId() == Id)
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        bool IsOwnerEquivalent(IControlledObject obj);
    };

    public interface IControlledObject
    {
        /**
         * Returns the group of this subject
         * @access public
         * @return Int
         */
        IGroup GetGroup();
        /**
         * Returns the owner of this object; a User object
         * @access public
         * @return Int
         */
        IUser GetOwner();

        /**
         * Returns the protection of this object; a Protection object
         * @access public
         * @return Int
         */
        Protection GetProtection();
    };

    public class Permission
    {
        public const int Deny = 0x0;
        public const int Full = 0xf;
        public const int ReadOnly = 0x1;
        public const int ReadWrite = 0x2;

        public const int B_Read    = 0x1;
        public const int B_Write   = 0x2;
        public const int B_Execute = 0x4;
        public const int B_Delete  = 0x8;

        public const int R = B_Read;
        public const int W = B_Write;
        public const int E = B_Execute;
        public const int D = B_Delete;
        public const int RW = B_Read | B_Write;
        public const int RWE = B_Read | B_Write | B_Execute;
        public const int RWED = B_Read | B_Write | B_Execute | B_Delete;
        public const int RED = B_Read | B_Execute | B_Delete;
        public const int RE = B_Read  | B_Execute ;

        /**
         * Construct either using a combined (int format encoding bits as RWED eg. 5=R E)
         * or by specifying as individual values;
         */
        public Permission(bool read, bool write, bool execute, bool delete)
        {
            permission = new System.Collections.Specialized.BitVector32();
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
        public Permission(int combined)
        {
            Read = (combined & 0x1) == 0x1;
            Write = (combined & 0x2) == 0x2;
            Execute = (combined & 0x4) == 0x4;
            Delete = (combined & 0x8) == 0x8;
        }
        System.Collections.Specialized.BitVector32 permission;

        public bool Read { get { return permission[B_Read]; } set { permission[B_Read] = value; } }
        public bool Write { get { return permission[B_Write]; } set { permission[B_Write] = value; } }
        public bool Execute { get { return permission[B_Execute]; } set { permission[B_Execute] = value; } }
        public bool Delete { get { return permission[B_Delete]; } set { permission[B_Delete] = value; } }

        public int Combined
        {
            get
            {
                return permission.Data;
            }
        }
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
            this.system = system;
            this.owner = owner;
            this.group = group;
            this.world = world;
        }
        /// <summary>
        /// construct using 4 bit masks, e.g. Permission.REWD
        /// /// </summary>
        /// <param name="system"></param>
        /// <param name="owner"></param>
        /// <param name="group"></param>
        /// <param name="world"></param>
        public Protection(int system, int owner, int group, int world)
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
        public static bool permitted(Action action, Permission permission)
        {
            switch (action)
            {
                case Action.Update:
                case Action.Write:
                case Action.Create:
                    return permission.Write;

                case Action.Read:
                    return permission.Read;

                case Action.Delete:
                    return permission.Delete;

                case Action.List:
                    // only items that have execute and read can be listed. this allows fine
                    // grained control of items appearing in lists - i.e. to remove an item from a list do not grant execute - just read.
                    return permission.Execute && permission.Read;
            }
            return false;
        }

        public static bool hasPriv(ISubject subject, Privilege PrivilegeName)
        {
            return subject.GetPrivileges().Contains(PrivilegeName);
        }

        public static bool IsPermitted(Action action, ISubject subject, IControlledObject obj, bool accessViaSystem = false)
        {
            var subjectGroups = subject.GetGroup();
            //
            // if the object is null then it appears safe to grant access.
            if (obj == null)
                return true;

            var protection = obj.GetProtection();
            var ok = false;

            /*
             * If the subject (user) has BYPASS then it allows access to everything in an uncontrolled (i.e. unix root)
             * type of manner, so just allow.
             */
            if (ReferenceMonitor.hasPriv(subject, Privilege.BYPASS))
                return true;

            /*
             * If the subject (user) has READALL then permit any read or list
             */
            if ((action == Action.Read
               || action == Action.List)
                && ReferenceMonitor.hasPriv(subject, Privilege.READALL))
            {
                return true;
            }

            //
            // least costly - so try this first.
            if (ReferenceMonitor.permitted(action, protection.world))
                return true;

            //
            // if system user - or have System Privilege then can access through the system protection.
            // accessViaSystem allows services to access via system protection and is part of the privilege elevation
            // and impersonation.
            if ((accessViaSystem || ReferenceMonitor.hasPriv(subject, Privilege.SYSPRV)) &&
                ReferenceMonitor.permitted(action, protection.system))
            {
                return true;
            }

            //
            // If the owner
            if (subject.IsOwnerEquivalent(obj) && ReferenceMonitor.permitted(action, protection.owner))
            {
                return true;
            }

            var accessViaGroup = ReferenceMonitor.hasPriv(subject, Privilege.GROUP); // access objects via group protection.

            /*
             * if the subject has group access (priv) or the group is the same 
             * between the subj and obj then grant access based on the group protection.
             */
            if ((accessViaGroup || subject.GetGroup() == obj.GetGroup())
                && ReferenceMonitor.permitted(action, protection.group))
                return true;

            //
            // only the owner or a subject with SECURITY priv can change permissions and protections.
            if (action == Action.Security)
                return subject.GetId() == obj.GetOwner().GetId() || ReferenceMonitor.hasPriv(subject, Privilege.SECURITY);
            return false;
        }
    }
}


