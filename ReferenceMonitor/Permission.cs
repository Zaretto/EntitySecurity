﻿namespace Zaretto.Security
{
    public class Permission
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

        /**
         * Construct either using a combined (byte format encoding bits as RWED eg. 5=R E)
         * or by specifying as individual values;
         */

        public Permission(bool read, bool write, bool execute, bool delete)
        {
            Combined = 0;
            Read = read;
            Write = write;
            Execute = execute;
            Delete = delete;
        }

        /// <summary>
        /// construct from a combined permission.
        /// 0: Read
        /// 2: Write
        /// 4: Execute
        /// 8: Delete
        /// </summary>
        /// <param name="combined"></param>
        public Permission(byte combined)
        {
            Read = (combined & B_Read) == B_Read;
            Write = (combined & B_Write) == B_Write;
            Execute = (combined & B_Execute) == B_Execute;
            Delete = (combined & B_Delete) == B_Delete;
        }

        public Permission(Permission from)
        {
            Read = from.Read;
            Write = from.Write;
            Execute = from.Execute;
            Delete = from.Delete;
        }

        public Permission(int combined)
        {
            Read = (combined & B_Read) == B_Read;
            Write = (combined & B_Write) == B_Write;
            Execute = (combined & B_Execute) == B_Execute;
            Delete = (combined & B_Delete) == B_Delete;
        }

        internal byte Combined;

        public bool Read
        {
            get
            {
                return (Combined & B_Read) == B_Read;
            }
            set
            {
                if (value)
                    Combined |= B_Read;
                else
                    Combined &= (byte)(~B_Read & 0xff);
            }
        }

        public bool Write
        {
            get
            {
                return (Combined & B_Write) == B_Write;
            }
            set
            {
                if (value)
                    Combined |= B_Write;
                else
                    Combined &= (byte)(~B_Write & 0xff);
            }
        }

        public bool Execute
        {
            get
            {
                return (Combined & B_Execute) == B_Execute;
            }
            set
            {
                if (value)
                    Combined |= B_Execute;
                else
                    Combined &= (byte)(~B_Execute & 0xff);
            }
        }

        public bool Delete
        {
            get
            {
                return (Combined & B_Delete) == B_Delete;
            }
            set
            {
                if (value)
                    Combined |= B_Delete;
                else
                    Combined &= (byte)(~B_Delete & 0xff);
            }
        }

        private static string add_permission_to_string(bool value, string if_set)
        {
            if (value)
                return if_set;
            else
                return "";
        }

        private string __toString()
        {
            return add_permission_to_string(Read, "R")
                + add_permission_to_string(Write, "W")
                + add_permission_to_string(Execute, "E")
                + add_permission_to_string(Delete, "D");
        }
    }
}