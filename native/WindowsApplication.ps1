function Start-GuardWindowsApplication([string]$AppId, [string]$Arguments) {
    if ([string]::IsNullOrWhiteSpace($AppId)) { throw 'An application user model ID is required.' }
    if (-not ('ClaudeGuard.WindowsApplication' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace ClaudeGuard {
    public static class WindowsApplication {
        [ComImport, Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IApplicationActivationManager {
            [PreserveSig]
            int ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string appId,
                [MarshalAs(UnmanagedType.LPWStr)] string arguments, uint options, out uint pid);
        }

        public static int Start(string appId, string arguments) {
            var type = Type.GetTypeFromCLSID(new Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C"));
            object manager = Activator.CreateInstance(type);
            try {
                uint pid;
                const uint NoErrorUi = 2;
                Marshal.ThrowExceptionForHR(((IApplicationActivationManager)manager)
                    .ActivateApplication(appId, arguments, NoErrorUi, out pid));
                if (pid == 0)
                    throw new InvalidOperationException("Windows application activation returned no process ID.");
                return checked((int)pid);
            } finally {
                Marshal.FinalReleaseComObject(manager);
            }
        }
    }
}
'@
    }
    [ClaudeGuard.WindowsApplication]::Start($AppId,$Arguments)
}
