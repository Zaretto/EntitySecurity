namespace Zaretto.Security
{
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