using System;

namespace Zaretto.System
{
    public class SystemStatusException : Exception
    {
        public enum ErrorSeverity
        {
            Success = 0,
            Information = 1,
            Warning = 2,
            Error = 4,
            Fatal = 8,
        }

        public enum ErrorIdent
        {
            OK = 0,
            NOPRIV = 0x10,
            ACCVIO = 0x10,
            NOUSER,
            FAIL,
            DBERROR,
            NOPARAM,
            NOVALUE,
            INVFMT,
            NOTFOUND,
        }

        public static string GetClassName(object obj)
        {
            return SimplifyClassName(obj.GetType().FullName);
        }

        public static string SimplifyClassName(string classname)
        {
            if (classname.Contains("System.Data.Entity.DynamicProxies"))
            {
                classname = classname.Replace("System.Data.Entity.DynamicProxies.", "").Split('_')[0];
            }
            return classname;
        }

        /// <summary>
        /// Severity of the error
        /// </summary>
        public ErrorSeverity Severity { get; set; }

        /// <summary>
        /// Identifies the type of the error
        /// </summary>
        public ErrorIdent Ident { get; set; }

        /// <summary>
        /// Specifies the name of the component that caused the exception
        /// </summary>
        public string Facility { get; set; }
        
        /// <summary>
        /// Explains the cause of the error. Should not contain % symbol.
        /// </summary>
        public string MessageText { get; set; }

        public SystemStatusException(string facility, ErrorSeverity severity, ErrorIdent ident, string message, Exception innerException)
            : base(String.Format("%{0}-{1}-{2}-{3}", facility, severity, ident, message), innerException)
        {
            MessageText = message;
            Severity = severity;
            Facility = facility;
            Ident = ident;
        }

        public SystemStatusException(string s)
            : base(s)
        {
            MessageText = s;
        }

        public SystemStatusException(string facility, ErrorSeverity severity, ErrorIdent ident, string message)
            : base(String.Format("%{0}-{1}-{2}-{3}", facility, severity, ident, message))
        {
            MessageText = message;
            Severity = severity;
            Facility = facility;
            Ident = ident;
        }

        public SystemStatusException(object obj, ErrorSeverity severity, ErrorIdent ident, string message)
            : base(String.Format("%{0}-{1}-{2}-{3}", GetClassName(obj), severity, ident, message))
        {
            MessageText = message;
            Severity = severity;
            Facility = GetClassName(obj);
            Ident = ident;
        }
    }
}