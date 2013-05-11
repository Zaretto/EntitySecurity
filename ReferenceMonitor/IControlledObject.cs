using System;

namespace Zaretto.Security
{
    public struct TUser
    { 
        internal uint? _value; 
        public TUser(uint? value) 
        { 
            this._value = value; 
        } 
        public static implicit operator uint?(TUser u) 
        { 
            return u._value; 
        } 
        public static implicit operator TUser(uint? val) 
        { 
            return new TUser(val); 
        } 
        public static implicit operator uint(TUser u) 
        { 
            if (u._value == null) 
            { 
                return 0; 
            } 
            else 
            { 
                return (uint)u._value; 
            } 
        } 
        public static implicit operator TUser(uint val) 
        { 
            return new TUser(val); 
        } 
        public override string ToString() 
        { 
            return ((uint?)this).ToString(); 
        } 
    } 

    public interface IControlledObject
    {
        /**
         * Returns the protection of this object; a Protection object
         * @access public
         * @return Int
         */

        Protection Protection { get; }

        TUser UserId { get; set; }
        TUser GroupId { get; set; }
    };
}