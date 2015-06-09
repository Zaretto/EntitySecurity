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
        /// the operations to which this group is applicable to. This allows us to have finely grained control of group
        /// operation
        /// </summary>
        Operation ApplicableOperation { get; set; }
    }
}
