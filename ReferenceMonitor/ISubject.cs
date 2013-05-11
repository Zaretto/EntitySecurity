namespace Zaretto.Security
{
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

        /// <summary>
        /// a way of identifying this to an external system - not a db key - just a reference
        /// </summary>
        string Identity { get; }
    }
}