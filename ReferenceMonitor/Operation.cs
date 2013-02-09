namespace Zaretto.Security
{
    public enum Operation
    {
        Read = 1 << 1,
        Write = 1 << 2,
        Update = 1 << 3,
        Delete = 1 << 4,
        Create = 1 << 5,
        List = 1 << 6,
        Security = 1 << 7,
    };
}