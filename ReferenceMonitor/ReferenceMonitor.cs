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
   *---------------------------------------------------------------------------*/

using System;

namespace Zaretto.Security
{

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


