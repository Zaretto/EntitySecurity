using System;
namespace Zaretto.Security
{
    /// <summary>
    /// Defines the protection applied to an IControlledObject. This consists of a set of 4 permissions for
    /// System, Owner, Group, World and is usually persisted in an integer.
    /// </summary>
    public interface IProtection
    {
         IPermission system { get; set; }

        IPermission owner { get; set; }

        IPermission group { get; set; }

        IPermission world { get; set; }

    }
}