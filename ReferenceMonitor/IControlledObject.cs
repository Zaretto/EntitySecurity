using System;

namespace Zaretto.Security
{
    public interface IControlledObject
    {
        /**
         * Returns the protection of this object; a Protection object
         * @access public
         * @return Int
         */

        Protection Protection { get; }

        Guid UserId { get; }

        Guid GroupId { get; }

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