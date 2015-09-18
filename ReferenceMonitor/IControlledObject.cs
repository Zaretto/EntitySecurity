using System;
using System.Collections.Generic;

namespace Zaretto.Security
{
    public interface IControlledObject
    {
        /**
         * Returns the protection of this object; a Protection object
         * @access public
         * @return Int
         */

        IProtection Protection { get; }

        Guid UserId { get; }

        /// <summary>
        /// List of groups that may access this object via group protection.
        /// </summary>
        List<IControlledObjectGroup> Groups { get; }
        
        /// <summary>
        /// for reference / display - the simplest identifiable form of the ID
        /// </summary>
        string SimpleId { get; }

        /// <summary>
        /// for reference / display - the text associated with the object owner
        /// </summary>
        string OwnerDescription { get; }
    };
}