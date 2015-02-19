using System;

namespace Zaretto.Security
{
    /// <summary>
    /// utility function for converting to GUID's - useful when needing to convert an int based DB index
    /// into a GUID suitable for the User/Group ID - as can convert with the id and name (using hash on name)
    /// to provide a reasonably unique result. see http://programmers.stackexchange.com/questions/49550/which-hashing-algorithm-is-best-for-uniqueness-and-speed
    ///
    /// </summary>
    public class GuidConverter
    {
        public static Guid GetGuidFromIntName(int id, string name)
        {
            byte[] bytes = new byte[16];
            BitConverter.GetBytes(FastHash.ComputeHash(name)).CopyTo(bytes, 0);
            BitConverter.GetBytes(id).CopyTo(bytes, 0);
            return new Guid(bytes);
        }

        public static Guid? GetGuidFromName(string p)
        {
            byte[] bytes = new byte[16];
            BitConverter.GetBytes(FastHash.ComputeHash(p)).CopyTo(bytes, 0);
            return new Guid(bytes);
        }

        public static Guid GetGuidFromInt(int id)
        {
            byte[] bytes = new byte[16]; // relying on this being initialized to zero
            BitConverter.GetBytes(id).CopyTo(bytes, 0);
            return new Guid(bytes);
        }
    }
}