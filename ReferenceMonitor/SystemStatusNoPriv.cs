using System;
using Zaretto.Security;

namespace Zaretto.System
{
    public class SystemStatusNoPriv : SystemStatusException
    {
        public SystemStatusNoPriv(IControlledObject obj, Zaretto.Security.Operation activity, ISubject user)
            : base(obj, ErrorSeverity.Fatal, ErrorIdent.NOPRIV,
            String.Format("Insufficient privilege or object protection violation. \n" +
                                                "Attempting to {0} {1}({2},{3}) {4} as {5}", activity, GetClassName(obj), obj.SimpleId, obj.OwnerDescription, obj.Protection, user.Identity))
        {
        }
    }
}