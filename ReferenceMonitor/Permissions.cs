using System;
using System.Collections.Generic;
using System.Text;

namespace Zaretto.Security
{
    /// <summary>
    /// convenience methods for the bitmapped permissions
    /// </summary>
    public class Permissions
    {
        public const byte Deny = 0x0;
        public const byte B_Read = 0x1;
        public const byte B_Write = 0x2;
        public const byte B_Execute = 0x4;
        public const byte B_Delete = 0x8;

        public const byte R = B_Read;
        public const byte W = B_Write;
        public const byte E = B_Execute;
        public const byte D = B_Delete;
        public const byte RW = B_Read | B_Write;
        public const byte RWE = B_Read | B_Write | B_Execute;
        public const byte RWED = B_Read | B_Write | B_Execute | B_Delete;
        public const byte RED = B_Read | B_Execute | B_Delete;
        public const byte RE = B_Read | B_Execute;
        public const int Standard = 0x3F00; //S:RW O:RWED G: W:
    }
}
