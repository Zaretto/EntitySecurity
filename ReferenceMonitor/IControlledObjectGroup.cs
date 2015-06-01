using System;
using System.Collections.Generic;
using System.Text;

namespace Zaretto.Security
{
    /// <summary>
    /// A Controlled Object Group has an ID and the permissions to which this group is applicable to.
    /// This allows fine grain controlled of the operations that a group may perform to an object via
    /// group protection.
    /// </summary>
    public interface IControlledObjectGroup : ISecurityGroup
    {
        /// <summary>
        /// the permissions to which this group is applicable to. This allows us to have different groups based on the REWD model.
        /// </summary>
        IPermission ApplicableTo { get;set;}
    }
}
