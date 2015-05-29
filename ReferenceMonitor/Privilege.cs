namespace Zaretto.Security
{
    /// <summary>
    /// Users can be assigned certain privileges that permit actions that would be protected.
    /// </summary>
    public enum Privilege
    {
        BYPASS = 1 << 1,    // Bypass object protection,                     All
        DIAGNOSE = 1 << 2,    // Diagnose objects                            Objects
        EXQUOTA = 1 << 3,    // May exceed quotas=                           Devour
        GROUP = 1 << 4,    // Access via group protection when not in group  Group
        IMPERSONATE = 1 << 5,    // Become another subject/user,             All
        IMPORT = 1 << 6,    // Perform import operations,                    Objects
        OPER = 1 << 7,    // Act as system operator,                         System
        READALL = 1 << 8,    // Read any object bypassing,                   Objects
        SECURITY = 1 << 9,    // Perform Security Operations,                System
        SETPRV = 1 << 10,   // Change own privilege levels,                  All
        SYSPRV = 1 << 11,   // Access objects via system protection,         All
        GROUPADMIN = 1 << 12,   // No meaning internally - external marker   None
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