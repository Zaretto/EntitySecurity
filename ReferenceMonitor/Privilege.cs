namespace Zaretto.Security
{
    public enum Privilege
    {
        BYPASS = 1 << 1,    // Bypass object protection,                      All
        DIAGNOSE = 1 << 2,    // Diagnose objects                               Objects
        EXQUOTA = 1 << 3,    // May exceed quotas=                             Devour
        GROUP = 1 << 4,    // Access via group protection when not in group = 0x0000, Group
        IMPERSONATE = 1 << 5,    // Become another subject/user,                   All
        IMPORT = 1 << 6,    // Perform import operations,                     Objects
        OPER = 1 << 7,    // Act as system operator,                        System
        READALL = 1 << 8,    // Read any object bypassing,                     Objects
        SECURITY = 1 << 9,    // Perform Security Operations,                   System
        SETPRV = 1 << 10,   // Change own privilege levels,                   All
        SYSPRV = 1 << 11,   // Access objects via system protection,          All
    };
}