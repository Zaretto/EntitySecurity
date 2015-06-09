namespace Zaretto.Security
{
    /// <summary>
    /// Operations that can be performed to an Object by a Subject. This can be extended by using extra bits that are unused and mapping these in
    /// an override of ReferenceMonitor.HasPermissionRequiredForOperation
    /// </summary>
    public enum Operation
    {
        /// <summary>
        /// Read from an object
        /// </summary>
        Read = 1 << 1,

        /// <summary>
        /// Write to an object.
        /// </summary>
        Write = 1 << 2,

        /// <summary>
        /// Delete an object
        /// </summary>
        Delete = 1 << 3,

        /// <summary>
        /// Create an object. Requires write permission so not completely seperated from Write in that having write access is enough to
        /// Create or Update; extra controls would have to be implemented by overriding PermissionRequiredForOperation
        /// </summary>
        Create = 1 << 4,

        /// <summary>
        /// List contents of an object
        /// </summary>
        List = 1 << 5,

        /// <summary>
        /// Perform Security operations; usually to prevent group or world from changing ownership or protection of an object.
        /// </summary>
        Security = 1 << 6,

        /// <summary>
        /// Assign something to an object; usually implies a subset of write. possible subset of execute or write.
        /// </summary>
        Assign = 1 << 7,

        /// <summary>
        /// Cancel an object. possible subset of execute.
        /// </summary>
        Cancel = 1 << 8,

        /// <summary>
        /// View an object; possible subset of read.
        /// </summary>
        View = 1 << 9,

        /// <summary>
        /// Move an object; possible subset of write.
        /// </summary>
        Move = 1 << 10,

        /// <summary>
        /// Submit an object for a secondary action or process. possible subset of execute.
        /// </summary>
        Submit = 1 << 11,

        /// <summary>
        /// All operations to be included; or the operation isn't specified.
        /// </summary>
        UnspecfiedOrAll = 0xffffff
    };

    public static class OperationExtensions
    {
        public static bool IsSet(this Operation target, Operation query)
        {
            return ((int)target & (int)query) == (int)query;
        }
        public static bool Contains(this Operation target, Operation query)
        {
            return ((int)target & (int)query) == (int)query;
        }
        public static Operation Append(this Operation target, Operation addition)
        {
            return (Operation)((int)target | (int)addition);
        }
    }
}