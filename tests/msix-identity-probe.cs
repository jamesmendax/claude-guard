using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class GuardMsixProbe
{
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    private static extern int GetCurrentPackageFullName(ref uint length, StringBuilder name);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool GetTokenInformation(IntPtr token, int kind, out int value, int size, out int returned);
    [DllImport("userenv.dll", CharSet=CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("advapi32.dll")]
    private static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long created, out long exited,
        out long kernel, out long user);

    [ComImport, Guid("2E941141-7F97-4756-BA1D-9DECDE894A3D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IApplicationActivationManager
    {
        [PreserveSig]
        int ActivateApplication([MarshalAs(UnmanagedType.LPWStr)] string appId,
            [MarshalAs(UnmanagedType.LPWStr)] string arguments, uint options, out uint processId);
    }

    public static uint Activate(string appId, string arguments)
    {
        Type managerType=Type.GetTypeFromCLSID(new Guid("45BA127D-10A8-46EA-8AB7-56EA9078943C"));
        object manager=Activator.CreateInstance(managerType);
        try
        {
            uint processId;
            Marshal.ThrowExceptionForHR(((IApplicationActivationManager)manager).ActivateApplication(appId,arguments,2,out processId));
            return processId;
        }
        finally { Marshal.FinalReleaseComObject(manager); }
    }

    public static int PipeClientId(NamedPipeServerStream pipe)
    {
        uint id;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out id))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return checked((int)id);
    }

    public static DateTime ReadCompletedExitUtc(Process process, DateTime expectedStartUtc)
    {
        if (!process.WaitForExit(5000))
            throw new InvalidOperationException("The observed Store process did not finish exiting.");
        long created, exited, kernel, user;
        if (!GetProcessTimes(process.SafeHandle, out created, out exited, out kernel, out user))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (created != expectedStartUtc.ToFileTimeUtc() || exited <= created)
            throw new InvalidOperationException("Windows did not report a completed lifetime for the same Store process.");
        return DateTime.FromFileTimeUtc(exited);
    }

    public static string PackageSid(string family)
    {
        IntPtr sid;
        Marshal.ThrowExceptionForHR(DeriveAppContainerSidFromAppContainerName(family, out sid));
        try { return new SecurityIdentifier(sid).Value; }
        finally { FreeSid(sid); }
    }
    internal static string CurrentPackageName()
    {
        uint length=0;
        int result=GetCurrentPackageFullName(ref length,null);
        if (result == 15700) return null; // APPMODEL_ERROR_NO_PACKAGE
        if (result != 122) throw new InvalidOperationException("PackageIdentityUnavailable");
        var name=new StringBuilder((int)length);
        if (GetCurrentPackageFullName(ref length,name) != 0) throw new InvalidOperationException("PackageIdentityUnavailable");
        return name.ToString();
    }
    public static int Main(string[] args)
    {
        if (args.Length != 3) return 1;
        Guid challenge;
        int port;
        if (!Guid.TryParseExact(args[0],"N",out challenge) || !Int32.TryParse(args[1],out port) || port < 1024 || port > 65535)
            return 1;
        string result;
        try
        {
            string name=CurrentPackageName();
            if (name != args[2])
                throw new InvalidOperationException("UnexpectedPackage");
            int container, returned;
            using (WindowsIdentity identity=WindowsIdentity.GetCurrent())
                if (!GetTokenInformation(identity.Token,29,out container,4,out returned) || container != 0)
                    throw new InvalidOperationException("ExpectedFullTrustDesktop");
            string sent="Sent";
            using (UdpClient udp=new UdpClient(AddressFamily.InterNetwork))
            {
                byte[] bytes=Encoding.ASCII.GetBytes(args[0]);
                try { udp.Send(bytes,bytes.Length,new IPEndPoint(IPAddress.Loopback,port)); }
                catch (SocketException ex) { sent=ex.SocketErrorCode.ToString(); }
            }
            using(Process current=Process.GetCurrentProcess())
                result=String.Join("|",args[0],name,container.ToString(),current.MainModule.FileName,sent);
        }
        catch(Exception ex){ result="ERROR|" + ex.GetType().Name + "|" + ex.Message; }
        using (NamedPipeClientStream pipe=new NamedPipeClientStream(".","GuardMsixFixture-"+args[0],PipeDirection.Out))
        {
            pipe.Connect(3000);
            using(StreamWriter writer=new StreamWriter(pipe)) writer.WriteLine(result);
        }
        return 0;
    }
}
