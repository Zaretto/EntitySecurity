# EntitySecurity

A lightweight .NET security **reference monitor** implementing the classic *subject / object / authorization* model from James P. Anderson's 1972 computer security planning study, with an API heavily influenced by OpenVMS object protection (System / Owner / Group / World permissions plus privileges).

The library is designed to be embedded into applications that need fine-grained, per-entity access control — typically domain/entity objects persisted through Entity Framework or similar ORMs, hence the name *EntitySecurity*.

---

## Contents

- [EntitySecurity](#entitysecurity)
  - [Contents](#contents)
  - [Concepts](#concepts)
  - [Solution layout](#solution-layout)
  - [Core API](#core-api)
    - [`ReferenceMonitor`](#referencemonitor)
    - [`IControlledObject`](#icontrolledobject)
    - [`ISubject`](#isubject)
    - [`IProtection` and `IPermission`](#iprotection-and-ipermission)
    - [`IControlledObjectOperation`](#icontrolledobjectoperation)
    - [`IControlledObjectGroup` / `ISecurityGroup`](#icontrolledobjectgroup--isecuritygroup)
    - [`Privilege`](#privilege)
  - [Access decision algorithm](#access-decision-algorithm)
  - [Protection encoding](#protection-encoding)
  - [Usage](#usage)
    - [Minimum integration](#minimum-integration)
    - [Worked example](#worked-example)
  - [Extending the model](#extending-the-model)
  - [Building and testing](#building-and-testing)
    - [Prerequisites](#prerequisites)
    - [Build](#build)
    - [Tests](#tests)
  - [References](#references)
  - [License](#license)

---

## Concepts

The security system is described in terms of four elements:

| Element | Role |
|---|---|
| **Subject** | An entity acting on behalf of a person (e.g. a logged-in user). Implements `ISubject`. |
| **Object** | An entity to be protected (a domain record, document, device, etc). Implements `IControlledObject`. |
| **Authorization database** | The per-object protection plus per-subject identity, group membership, and privileges. In this library the data live on the objects themselves (`Protection`, `UserId`, `Groups`) and on the subject (privilege mask, group list). |
| **Reference monitor** | The component that authorizes every access attempt by a subject to an object. `ReferenceMonitor.IsPermitted(...)` is the single decision point. |

The reference monitor enforces the policy by granting or denying an *operation* (Read, Write, Delete, Create, List, Security, …) on an object for a given subject, based on the object's `Protection`, the subject's identity, the subject's group membership, and the subject's privileges.

---

## Solution layout

```
EntitySecurity/
├── ReferenceMonitor.sln         # Visual Studio solution
├── ReferenceMonitor/            # The library itself (assembly: EntitySecurity)
│   ├── ReferenceMonitor.cs      # Main decision logic
│   ├── IControlledObject.cs     # Object contract
│   ├── ISubject.cs              # Subject contract
│   ├── IProtection.cs           # S/O/G/W protection
│   ├── IPermission.cs           # R/W/E/D permission bits
│   ├── IControlledObjectOperation.cs
│   ├── IControlledObjectGroup.cs
│   ├── ISecurityGroup.cs
│   ├── Permissions.cs           # Bitmask constants
│   ├── Privilege.cs             # Privilege flags + helper
│   ├── FastHash.cs
│   ├── GuidConverter.cs
│   └── SystemStatusException.cs / SystemStatusNoPriv.cs
├── TestObjects/                 # Reference implementations used by tests and
│   │                            # useful as starting points for real applications.
│   ├── User.cs                  # Sample ISubject
│   ├── TestItem.cs              # Sample IControlledObject
│   ├── Permission.cs            # Sample IPermission (byte-packed)
│   ├── Protection.cs            # Sample IProtection (16-bit packed SOGW)
│   ├── TestObjectGroup.cs       # Sample IControlledObjectGroup
│   ├── TestUser.cs              # Sample ISecurityGroup
│   └── MyReferenceMonitor.cs    # Shows how to extend ReferenceMonitor
├── UnitTests/                   # MSTest unit tests for the monitor
└── packages/                    # NuGet packages (restored)
```

The library is an SDK-style multi-target assembly — `ReferenceMonitor/ReferenceMonitor.csproj` builds for `net5.0`, `netstandard2.0`, `netstandard1.0`, `net4.6` and `net4.8`, and is published to NuGet as [`EntitySecurity`](https://www.nuget.org/packages/EntitySecurity). Namespace: `Zaretto.Security`.

> `ReferenceMonitor/EntitySecurity.csproj` is an older portable (`Profile328`, .NET 4.0) project retained alongside the SDK-style one; the solution and the NuGet package are built from `ReferenceMonitor.csproj`.

---

## Core API

### `ReferenceMonitor`

```csharp
namespace Zaretto.Security;

public class ReferenceMonitor
{
    public virtual bool IsPermitted(
        IControlledObjectOperation operation,
        ISubject subject,
        IControlledObject obj,
        bool accessViaSystem = false);

    public virtual bool HasPermissionRequiredForOperation(
        IControlledObjectOperation operation,
        IPermission permission);

    public virtual void ThrowIfNotPermitted(
        IControlledObjectOperation operation,
        ISubject currentUser,
        IControlledObject obj,
        bool accessViaSystem = false);
}
```

- `IsPermitted` returns `true` / `false`.
- `ThrowIfNotPermitted` throws `Zaretto.System.SystemStatusNoPriv` when the decision is deny — convenient at the boundary of a service call.
- `HasPermissionRequiredForOperation` maps an *operation* to a *permission bit* (e.g. `Read → permission.Read`) and is the primary extension point for custom operations.

### `IControlledObject`

Any domain object that must be protected implements this interface:

```csharp
public interface IControlledObject
{
    IProtection Protection { get; }
    Guid UserId { get; }                               // owner
    List<IControlledObjectGroup> Groups { get; }       // groups granting access
    string SimpleId { get; }                           // for logs/UI
    string OwnerDescription { get; }                   // for logs/UI
}
```

The owner is identified by `UserId` (a `Guid`). `Groups` is the list of `IControlledObjectGroup`s that may access the object via *group* protection — each group declares which operations it applies to, so a user can belong to a read-only group for an object without gaining write access through group protection.

> If `obj == null`, `subject == null`, or `obj.UserId == Guid.Empty`, access is granted. This intentionally allows lazy-loaded or un-owned entities to flow through; if you do not want that, override `IsPermitted`.

### `ISubject`

```csharp
public interface ISubject
{
    bool HasPrivilege(Privilege p);
    void AddPrivilege(Privilege p);
    void RemovePrivilege(Privilege p);

    bool IsOwnerEquivalent(IControlledObjectOperation operation, IControlledObject obj);
    bool IsGroupEquivalent(IControlledObjectOperation operation, IControlledObject obj);

    string Identity { get; }
}
```

`IsOwnerEquivalent` and `IsGroupEquivalent` are deliberately abstract: the concrete subject implementation decides what it means to "be the owner" or "be in the group". In the simplest case `IsOwnerEquivalent` is `obj.UserId == this.Id` and `IsGroupEquivalent` is "one of my group IDs matches one of the object's groups whose `ApplicableOperation` contains the requested operation" — see `TestObjects/User.cs` for a worked example.

### `IProtection` and `IPermission`

```csharp
public interface IProtection
{
    IPermission system { get; }
    IPermission owner  { get; }
    IPermission group  { get; }
    IPermission world  { get; }
}

public interface IPermission
{
    bool Read    { get; set; }
    bool Write   { get; set; }
    bool Execute { get; set; }
    bool Delete  { get; set; }
}
```

An object's *protection* is four independent permission sets, one for each access class. Each set carries the four classic permission bits (R, W, E, D).

### `IControlledObjectOperation`

A flags enum of things a subject can attempt to do:

`Read`, `Write`, `Delete`, `Create`, `List`, `Security`, `Assign`, `Cancel`, `View`, `Move`, `Submit`, `Impersonate`, `UnspecfiedOrAll`.

Default mapping (see `ReferenceMonitor.HasPermissionRequiredForOperation`):

| Operation | Required permission bit |
|---|---|
| `Read`     | `Read` |
| `Write`    | `Write` |
| `Create`   | `Write` |
| `Delete`   | `Delete` |
| `List`     | `Read` **and** `Execute` |
| `Security` | *none* — governed by ownership or `SECURITY` privilege only |

Additional operations (`Assign`, `Cancel`, `View`, `Move`, `Submit`, `Impersonate`) are reserved but unmapped by default; override `HasPermissionRequiredForOperation` to map them. `TestObjects/MyReferenceMonitor.cs` shows `Assign` mapped to `permission.Write`.

Extension helpers on the enum:

```csharp
op.IsSet(IControlledObjectOperation.Read);
op.Contains(IControlledObjectOperation.Read);
op.Append(IControlledObjectOperation.Write);   // bitwise OR
```

### `IControlledObjectGroup` / `ISecurityGroup`

```csharp
public interface ISecurityGroup
{
    Guid Id { get; }
}

public interface IControlledObjectGroup : ISecurityGroup
{
    IControlledObjectOperation ApplicableOperation { get; }
}
```

An `IControlledObjectGroup` is a group *entry on an object*: it says "members of group X may use me for operations Y". This is how the library separates a *read group* from a *write group* on the same object without needing two distinct notions of group membership on the subject.

### `Privilege`

A flags enum of privileges a subject may hold:

| Privilege | Meaning |
|---|---|
| `BYPASS`      | Bypass all object protection (root-like). |
| `DIAGNOSE`    | Diagnose objects. |
| `EXQUOTA`     | May exceed quotas. |
| `GROUP`       | Access via group protection even when not actually in the group. |
| `IMPERSONATE` | Become another subject. |
| `IMPORT`      | Perform import operations. |
| `OPER`        | Act as system operator. |
| `READALL`     | Read or list any object regardless of protection. |
| `SECURITY`    | May change protection/ownership of objects you do not own. |
| `SETPRV`      | Change own privilege levels. |
| `SYSPRV`      | Access objects via the *system* protection field. |
| `GROUPADMIN`, `GROUPSYSTEM`, `USERPRIV1`, `USERPRIV2` | Not used internally — reserved markers for the host application. |

`PrivilegeHelper.HasPrivilege(required, assignedMask)` is available for test-by-mask where useful.

---

## Access decision algorithm

`ReferenceMonitor.IsPermitted` evaluates the following in order, returning `true` as soon as any rule grants access:

1. **Null / unowned short-circuit** — `obj == null`, `subject == null`, or `obj.UserId == Guid.Empty` → allow.
2. **World** — the world permission grants the operation → allow.
3. **Owner** — the owner permission grants the operation **and** the subject is owner-equivalent → allow.
4. **System** — the system permission grants the operation **and** either `accessViaSystem == true` or the subject has `SYSPRV` → allow.
5. **Security operations** — if the operation is `Security`, allow only if the subject is owner-equivalent or holds `SECURITY`.
6. **Group** — the group permission grants the operation **and** (the subject is group-equivalent for this operation *or* holds `GROUP`) → allow.
7. **`BYPASS`** — subject holds `BYPASS` → allow anything.
8. **`READALL`** — operation is `Read` or `List` and subject holds `READALL` → allow.
9. Otherwise → deny.

The ordering is performance-motivated: the cheapest tests (world, owner identity) come before the group membership test, which may scan collections.

`accessViaSystem = true` is intended for trusted services acting on behalf of a user — used as part of privilege elevation / impersonation flows.

---

## Protection encoding

The reference `Protection` implementation in `TestObjects/Protection.cs` packs four R/W/E/D permission nibbles into a 16-bit integer so a whole protection can be stored in a single DB column:

```
bit:  15  14  13  12 | 11  10  9   8  |  7   6   5   4  |  3   2   1   0
      S_D S_E S_W S_R  O_D O_E O_W O_R   G_D G_E G_W G_R   W_D W_E W_W W_R
      \_____System___/\_____Owner_____/\_____Group_____/\_____World_____/
```

Or, more simply: `0xSOGW` where each nibble is the combined permission `(D<<3)|(E<<2)|(W<<1)|(R)`.

Useful constants from `Zaretto.Security.Permissions`:

```csharp
Permissions.R       // 0x1  Read
Permissions.W       // 0x2  Write
Permissions.E       // 0x4  Execute
Permissions.D       // 0x8  Delete
Permissions.RW      // 0x3
Permissions.RWE     // 0x7
Permissions.RWED    // 0xF
Permissions.Standard // 0x3F00  -> S:RW O:RWED G: W:
```

Examples:

| Value     | System | Owner | Group | World |
|---|---|---|---|---|
| `0xFF00`  | RWED   | RWED  | —     | —     |
| `0xFFD1`  | RWED   | RWED  | RWE   | R     |
| `0x3F00`  | RW     | RWED  | —     | —     |
| `0x0`     | —      | —     | —     | —     |

---

## Usage

### Minimum integration

1. Reference the `EntitySecurity` assembly.
2. Implement `IControlledObject` on each domain entity you want protected.
3. Implement `ISubject` on your user / principal type.
4. Implement `IPermission`, `IProtection`, `IControlledObjectGroup` if the provided reference implementations don't suit your persistence story (or copy them from `TestObjects/`).
5. At every access site, consult a `ReferenceMonitor` (usually a long-lived singleton):

```csharp
using Zaretto.Security;

var monitor = new ReferenceMonitor();

if (!monitor.IsPermitted(IControlledObjectOperation.Write, currentUser, invoice))
    return Forbid();

// or, throwing style, idiomatic at service boundaries:
monitor.ThrowIfNotPermitted(IControlledObjectOperation.Delete, currentUser, invoice);
```

### Worked example

```csharp
// Groups (with the operations they apply to)
var readGroup  = new TestGroup(Guid.NewGuid(), IControlledObjectOperation.Read);
var writeGroup = new TestGroup(
    Guid.NewGuid(),
    IControlledObjectOperation.Write
        .Append(IControlledObjectOperation.Read)
        .Append(IControlledObjectOperation.Delete));

// Users in those groups
var alice = new User(Guid.NewGuid(), readGroup, writeGroup);
var bob   = new User(Guid.NewGuid(), readGroup);          // read-only

// Object owned by Alice with Standard protection (S:RW O:RWED G: W:)
var doc = new TestItem(alice, readGroup, writeGroup,
                       new Protection(Permissions.Standard));

var rm = new ReferenceMonitor();

rm.IsPermitted(IControlledObjectOperation.Read,  alice, doc);  // true  (owner)
rm.IsPermitted(IControlledObjectOperation.Write, alice, doc);  // true  (owner)
rm.IsPermitted(IControlledObjectOperation.Read,  bob,   doc);  // false (no world R, not in group for read via protection)

// Grant Bob the READALL privilege — he can now read anything
bob.AddPrivilege(Privilege.READALL);
rm.IsPermitted(IControlledObjectOperation.Read,  bob,   doc);  // true
rm.IsPermitted(IControlledObjectOperation.Write, bob,   doc);  // still false

// BYPASS is the big hammer
bob.AddPrivilege(Privilege.BYPASS);
rm.IsPermitted(IControlledObjectOperation.Delete, bob, doc);   // true
```

Full end-to-end scenarios are in `UnitTests/ReferenceMonitorTests.cs`.

---

## Extending the model

Common extension points:

**New operations.** Add a flag bit to `IControlledObjectOperation` (the enum has spare bits through `1 << 12`; above that you'd edit the enum), then subclass `ReferenceMonitor` and override `HasPermissionRequiredForOperation` to map it to the appropriate permission bit. See `TestObjects/MyReferenceMonitor.cs`:

```csharp
public class MyReferenceMonitor : ReferenceMonitor
{
    public override bool HasPermissionRequiredForOperation(
        IControlledObjectOperation operation,
        IPermission permission)
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
```

**Fine-grained group/owner checks.** `IsOwnerEquivalent` and `IsGroupEquivalent` on the subject receive the operation being attempted, so ownership or group membership can be made operation-specific (e.g. "I own this record for reading but not for deletion").

**Custom privileges.** The `Privilege` enum has `USERPRIV1` / `USERPRIV2` for application-specific privileges, plus all bits from `1 << 16` onwards are free if you want more.

**Policy overrides.** Override `IsPermitted` itself to add audit trail recording (the one element of the Anderson model not implemented here — logging is left to the embedding application), mandatory-access-control labels, time-of-day restrictions, etc.

---

## Building and testing

### Prerequisites

- The **.NET SDK** (5.0+ will build all targets; older SDKs will build the subset they support).
- .NET Framework 4.6 / 4.8 reference assemblies installed if you want those targets to build (Windows + Visual Studio Build Tools).
- Visual Studio 2019 or later is convenient but not required — the command line is sufficient.

### Build

```cmd
dotnet restore ReferenceMonitor.sln
dotnet build   ReferenceMonitor.sln -c Release
dotnet pack    ReferenceMonitor\ReferenceMonitor.csproj -c Release
```

`GeneratePackageOnBuild=true` is set in the csproj, so a release build also produces the `.nupkg`. Open `ReferenceMonitor.sln` in Visual Studio if you prefer the IDE.

### Tests

`UnitTests/` is an MSTest project. Run it from Visual Studio's Test Explorer, or from the command line:

```cmd
vstest.console.exe UnitTests\bin\Debug\UnitTests.dll
```

The suite covers the world/owner/group/system decision paths, the privilege overrides (`BYPASS`, `READALL`, `SECURITY`), and the per-group-per-operation refinement via `ApplicableOperation`.

---

## References

- James P. Anderson, *Computer Security Technology Planning Study*, ESD-TR-73-51 Vol. II, October 1972 — <http://csrc.nist.gov/publications/history/ande72.pdf>
- *OpenVMS Guide to System Security*, AA-Q2HLE-TE — ([http://h71000.www7.hp.com/doc/73final/6346/6346pro.html archived](https://web.archive.org/web/20090830203935/http://h71000.www7.hp.com/doc/73final/6346/6346pro.html))
- *Record interface segmentation — Object Mapping* — <http://chateau-logic.com/content/record-interface-segmentation-object-mapping>

---

## License

Licensed under the **GNU General Public License, version 3 or (at your option) any later version** (GPL-3.0-or-later). See [`LICENSE`](LICENSE) for the full text, or <https://www.gnu.org/licenses/gpl-3.0.html>.

Copyright © 1999–2026 Richard Harrison.

Originally written in 1999, ported to PHP in 2012 and to C# in January 2013. Published on NuGet as [`EntitySecurity`](https://www.nuget.org/packages/EntitySecurity). See source-file headers for per-file attribution.
