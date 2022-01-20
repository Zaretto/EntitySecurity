using System;
using System.Collections.Generic;
using System.Text;
using Zaretto.Security;

namespace TestObjects
{
    /// <summary>
    /// This version of the reference monitor defines which permission field the Assign operation maps to.
    /// The basic operations (system, world) will use this permission; however the fine grained (that call IsOwnerEquivalent or IsGroupEquivalent)
    /// can further refine the applicability of the group / owner tests to exlcude this operation if required.
    /// </summary>
    public class MyReferenceMonitor : ReferenceMonitor
    {
        public override bool HasPermissionRequiredForOperation(IControlledObjectOperation operation, IPermission permission)
        {
            switch (operation)
            {
                case IControlledObjectOperation.Assign:
                    return permission.Write;
                default:
                    return base.HasPermissionRequiredForOperation(operation, permission);
            }
        }
    }
}