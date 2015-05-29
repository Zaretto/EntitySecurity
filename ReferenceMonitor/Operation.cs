namespace Zaretto.Security
{
    /// <summary>
    /// Operations that can be performed to an Object by a Subject
    /// </summary>
    public enum Operation
    {
        Read = 1 << 1,
        Write = 1 << 2,
        Delete = 1 << 3,
        Create = 1 << 4,
        List = 1 << 5,
        Security = 1 << 6,
    };
}