using System;
namespace Zaretto.Security
{
    /// <summary>
    /// The permissions that a required to access an object.
    /// </summary>
    public interface IPermission
    {

        bool Read {get;set;}
        bool Write{get;set;}

        bool Execute{get;set;}

        bool Delete{get;set;}
    }
}