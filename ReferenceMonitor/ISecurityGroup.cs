using System;
using System.Collections.Generic;
using System.Text;

namespace Zaretto.Security
{
    /// <summary>
    /// Subject group. A subject may be in one or more groups.
    /// </summary>
    public interface ISecurityGroup
    {
        Guid Id { get; set; }
    }
}
