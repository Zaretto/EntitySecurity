using System.Reflection;
using System.Runtime.InteropServices;

// General Information about an assembly is controlled through the following
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
[assembly: AssemblyTitle("Zaretto Security")]
[assembly: AssemblyDescription("Provides Security Implementation related features, currently a ReferenceMonitor and required interfaces")]
#if DEBUG
[assembly: AssemblyConfiguration("Debug")]
#else
[assembly: AssemblyConfiguration("Release")]
#endif
[assembly: AssemblyCompany("Zaretto")]
[assembly: AssemblyProduct("ZarettoSecurity")]
[assembly: AssemblyCopyright("Copyright ©  2015 Richard Hazrrison")]
[assembly: AssemblyCulture("")]

// Setting ComVisible to false makes the types in this assembly not visible
// to COM components.  If you need to access a type in this assembly from
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("5e5f6419-c3a0-49e0-a049-707ca97731b1")]

[assembly: AssemblyVersion("2.0.0.0")]
[assembly: AssemblyFileVersion("2.0.0.0")]