namespace Zaretto.Security
{
    /// <summary>
    /// Users can be assigned certain privileges that permit actions that would be protected.
    /// </summary>
    /// <note>
    /// The GROUPADMIN GROUPSYSTEM USERPRIV1 USERPRIV2 are to allow privileges to be added to the implementations and still retain
    /// values defined here. It is also possible to extend beyond the values defined here using bits 16 onwards.
    /// </note>
    public enum Privilege
    {
        /// <summary>
        /// Bypass object protection,                     All
        /// </summary>
        BYPASS = 1 << 1,

        /// <summary>
        /// Diagnose objects                            Objects
        /// </summary>
        DIAGNOSE = 1 << 2,

        /// <summary>
        /// May exceed quotas                           Devour
        /// </summary>
        EXQUOTA = 1 << 3,

        /// <summary>
        /// Access via group protection when not in group  Group
        /// </summary>
        GROUP = 1 << 4,

        /// <summary>
        /// Become another subject/user             All
        /// </summary>
        IMPERSONATE = 1 << 5,

        /// <summary>
        /// Perform import operations,                    Objects
        /// </summary>
        IMPORT = 1 << 6,

        /// <summary>
        /// Act as system operator,                         System
        /// </summary>
        OPER = 1 << 7,

        /// <summary>
        /// Read any object bypassing,                   Objects
        /// </summary>
        READALL = 1 << 8,

        /// <summary>
        /// Perform Security Operations,                System
        /// </summary>
        SECURITY = 1 << 9,

        /// <summary>
        /// Change own privilege levels,                  All
        /// </summary>
        SETPRV = 1 << 10,

        /// <summary>
        /// Access objects via system protection,         All
        /// </summary>
        SYSPRV = 1 << 11,

        /// <summary>
        /// No meaning internally - external marker   None
        /// </summary>
        GROUPADMIN = 1 << 12,

        /// <summary>
        /// No meaning internally - external marker   None
        /// </summary>
        GROUPSYSTEM = 1 << 13,

        /// <summary>
        /// No meaning internally - external marker   None
        /// </summary>
        USERPRIV1 = 1 << 14,

        /// <summary>
        /// No meaning internally - external marker   None
        /// </summary>
        USERPRIV2 = 1 << 15,
    };

    public class PrivilegeHelper
    {
        /// <summary>
        /// Test if specific privileges are set.
        /// </summary>
        /// <param name="RequiredPrivileges">Required privs</param>
        /// <param name="AssignedPrivileges">Assigned Privileges</param>
        /// <returns></returns>
        public static bool HasPrivilege(Privilege RequiredPrivileges, int AssignedPrivileges)
        {
            return ((int)AssignedPrivileges & (int)RequiredPrivileges) == (int)RequiredPrivileges;
        }
    }
}
