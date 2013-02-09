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

        Guid UserId { get; set; }

        Guid GroupId { get; set; }
    };
}