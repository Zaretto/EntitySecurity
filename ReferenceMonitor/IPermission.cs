using System;
using System.Collections.Generic;
using System.Text;

namespace Zaretto.Security
{
    public interface IPermission
    {
        bool Read{get;}
        bool Write{get;}
        bool Execute{get;}
        bool Delete { get; }

        byte GetCombined();
    }
}
