using System;
namespace Zaretto.Security
{
    /// <summary>
    /// Defines the protection applied to an IControlledObject. This consists of a set of 4 permissions for
    /// System, Owner, Group, World and is usually persisted in an integer.
    /// </summary>
    public interface IProtection
    {
         IPermission system { get;  }

        IPermission owner { get;  }

        IPermission group { get; }

        IPermission world { get;  }

    }
}