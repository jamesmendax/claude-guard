using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

internal static partial class GuardSetup
{
    private const string RegionToolName="ClaudeGuardSettings.exe";

    private static string UserRegionHome()
    {
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ClaudeVPNGuard");
    }

    private static string PrepareUserRegion()
    {
        // This entire path is used only by a non-elevated user. The privileged installer never loads this cache.
        using(var user=WindowsIdentity.GetCurrent())
            if(new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator))
                throw new InvalidOperationException("请从普通 Windows 会话打开地区与语言。");
        SetTrustedProcessEnvironment();
        using(FileStream source=OpenImage())
        {
            byte[] bytes=ReadBoundImage(source);
            string digest;
            using(var stream=new MemoryStream(bytes,false)) digest=Hash(stream);
            string local=UserRegionHome(), releases=Path.Combine(local,"regional-releases");
            string version=Path.Combine(releases,digest.ToLowerInvariant());
            string payload=Path.Combine(version,"payload");
            foreach(string dir in new[]{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),local,releases})
            {
                Directory.CreateDirectory(dir); AssertNotLink(dir);
            }
            using(var user=WindowsIdentity.GetCurrent())
            using(var mutex=new Mutex(false,@"Local\ClaudeGuardRegionCache-"+user.User.Value))
            {
                bool held=false;
                try
                {
                    try { held=mutex.WaitOne(TimeSpan.FromSeconds(15)); } catch(AbandonedMutexException){ held=true; }
                    if(!held) throw new InvalidOperationException("另一个 Guard 正在准备地区设置。");
                    var bundle=new Bundle();
                    if(!Directory.Exists(version))
                    {
                        string pending=Path.Combine(releases,"prepare-"+Guid.NewGuid().ToString("N"));
                        Directory.CreateDirectory(pending); AssertNotLink(pending);
                        string data=Path.Combine(pending,"payload");
                        Directory.CreateDirectory(data); AssertNotLink(data);
                        bundle.ReadArchive(data);
                        bundle.VerifyTree(data,false,null);
                        using(var output=new FileStream(Path.Combine(pending,RegionToolName),FileMode.CreateNew,FileAccess.Write,FileShare.None))
                        { output.Write(bytes,0,bytes.Length); output.Flush(true); }
                        Directory.Move(pending,version);
                    }
                    AssertNotLink(version); AssertNotLink(payload);
                    string executable=Path.Combine(version,RegionToolName);
                    AssertNotLink(executable);
                    if(HashFile(executable)!=digest) throw new InvalidDataException("地区设置程序未通过完整性核对。");
                    bundle.VerifyTree(payload,false,null);
                }
                finally { if(held) mutex.ReleaseMutex(); }
            }
            return payload;
        }
    }

    private static object RunRegionAction(string root,string command,string country,string ipv4,string request)
    {
        var state=InitialSessionState.CreateDefault2();
        state.ExecutionPolicy=Microsoft.PowerShell.ExecutionPolicy.Bypass;
        using(var session=RunspaceFactory.CreateRunspace(state))
        {
            session.ApartmentState=ApartmentState.STA; session.ThreadOptions=PSThreadOptions.ReuseThread; session.Open();
            using(PowerShell ps=PowerShell.Create())
            {
                ps.Runspace=session;
                ps.AddScript("param($path) . $path",false).AddParameter("path",Path.Combine(root,@"release\guard-user-region.ps1"));
                ps.Invoke();
                if(ps.HadErrors) throw new InvalidOperationException("无法载入地区与语言功能。");
                ps.Commands.Clear();
                ps.AddCommand(command).AddParameter("BundleRoot",root);
                if(country!=null) ps.AddParameter("CountryCode",country).AddParameter("ExpectedIpv4",ipv4).AddParameter("RequestId",request);
                ps.AddCommand("ConvertTo-Json").AddParameter("Depth",12).AddParameter("Compress");
                var output=ps.Invoke();
                // The regional action captures recoverable Windows errors in its typed receipt.
                if(output.Count>1 || (output.Count==0 && ps.HadErrors))
                    throw new InvalidOperationException("地区与语言操作未完成，请查看本机回执。");
                if(output.Count==0) return null;
                object value=new JavaScriptSerializer { MaxJsonLength=262144 }.DeserializeObject(output[0].ToString());
                if(command=="Invoke-GuardUserRegion")
                {
                    var receipt=value as IDictionary;
                    if(receipt==null || receipt["RequestId"] as string!=request || String.IsNullOrEmpty(receipt["Outcome"] as string))
                        throw new InvalidOperationException("地区设置回执未通过核对。");
                }
                return value;
            }
        }
    }

    private static int RunUserRegionMode(string[] args)
    {
        bool show=args[0]=="--user-region-settings";
        if((show && args.Length!=1) || (!show && (args.Length<3 || args.Length>4 || !IsCurrentNodeTarget(args[1],args[2]) ||
            (args.Length==4 && !Regex.IsMatch(args[3],@"\A[a-f0-9]{32}\z"))))) return 2;
        RequireNativeAmd64();
        string payload=PrepareUserRegion();
        if(show)
        {
            return GuardUserRegionWindow.Run(
                ()=>RunRegionAction(payload,"Get-GuardUserRegionResult",null,null,null) as IDictionary,
                (country,ip)=>IsCurrentNodeTarget(country,ip) ? RunRegionAction(payload,"Invoke-GuardUserRegion",country,ip,Guid.NewGuid().ToString("N")) as IDictionary : null,
                ()=>RunRegionAction(payload,"Confirm-GuardUserRegionSite",null,null,null) as string,
                ClaudeGuard.SiteLanguage.OpenManualSetting);
        }
        string id=args.Length==4 ? args[3] : Guid.NewGuid().ToString("N");
        var result=RunRegionAction(payload,"Invoke-GuardUserRegion",args[1],args[2],id) as IDictionary;
        if(result==null || !String.Equals(result["RequestId"] as string,id,StringComparison.Ordinal)) return 1;
        string outcome=result["Outcome"] as string;
        if(outcome=="Applied" || outcome=="ManualRequired")
        {
            try { InstallRegionLink(Path.Combine(Path.GetDirectoryName(payload),RegionToolName)); }
            catch { result["SettingsLinkCreated"]=false; }
        }
        Console.WriteLine(new JavaScriptSerializer().Serialize(result));
        return outcome=="Applied" || outcome=="ManualRequired" ? 0 : 1;
    }

    private static void InstallRegionLink(string launcher)
    {
        string programs=Environment.GetFolderPath(Environment.SpecialFolder.Programs);
        AssertNotLink(programs);
        string path=Path.Combine(programs,"Claude Guard Region Settings.lnk");
        string temporary=Path.Combine(programs,"ClaudeGuardRegion-"+Guid.NewGuid().ToString("N")+".lnk");
        string backup=temporary+".bak", cache=Path.Combine(UserRegionHome(),"regional-releases");
        object shell=null, previous=null, shortcut=null;
        try
        {
            shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell",true));
            if(File.Exists(path))
            {
                AssertNotLink(path);
                previous=shell.GetType().InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{path});
                string old=(string)previous.GetType().InvokeMember("TargetPath",BindingFlags.GetProperty,null,previous,null);
                string args=(string)previous.GetType().InvokeMember("Arguments",BindingFlags.GetProperty,null,previous,null);
                if(String.Equals(old,launcher,StringComparison.OrdinalIgnoreCase) && args=="--user-region-settings") return;
                if(String.IsNullOrEmpty(old) || !String.Equals(Path.GetFileName(old),RegionToolName,StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(Path.GetDirectoryName(Path.GetDirectoryName(old)),cache,StringComparison.OrdinalIgnoreCase) ||
                    args!="--user-region-settings") return;
            }
            shortcut=shell.GetType().InvokeMember("CreateShortcut",BindingFlags.InvokeMethod,null,shell,new object[]{temporary});
            Type t=shortcut.GetType();
            t.InvokeMember("TargetPath",BindingFlags.SetProperty,null,shortcut,new object[]{launcher});
            t.InvokeMember("Arguments",BindingFlags.SetProperty,null,shortcut,new object[]{"--user-region-settings"});
            t.InvokeMember("WorkingDirectory",BindingFlags.SetProperty,null,shortcut,new object[]{Path.GetDirectoryName(launcher)});
            t.InvokeMember("Description",BindingFlags.SetProperty,null,shortcut,new object[]{"Claude Guard 地区与语言设置"});
            t.InvokeMember("Save",BindingFlags.InvokeMethod,null,shortcut,null);
            if(File.Exists(path)) File.Replace(temporary,path,backup); else File.Move(temporary,path);
        }
        finally
        {
            foreach(object item in new[]{shortcut,previous,shell}) if(item!=null && Marshal.IsComObject(item)) Marshal.ReleaseComObject(item);
            if(File.Exists(temporary)) File.Delete(temporary);
            if(File.Exists(backup)) File.Delete(backup);
        }
    }

    internal static IDictionary StartUserRegion(string country,string ipv4)
    {
        if(String.IsNullOrEmpty(country) || String.IsNullOrEmpty(ipv4) || !IsCurrentNodeTarget(country,ipv4))
            throw new ArgumentException("地区或 IPv4 无效。");
        string id=Guid.NewGuid().ToString("N");
        using(var user=WindowsIdentity.GetCurrent())
            if(!new WindowsPrincipal(user).IsInRole(WindowsBuiltInRole.Administrator))
                return RunRegionAction(PrepareUserRegion(),"Invoke-GuardUserRegion",country,ipv4,id) as IDictionary;
        ClaudeGuard.SiteLanguage.StartUserRegionHelper(country,ipv4,id);
        string record=Path.Combine(UserRegionHome(),"user-region-result.json");
        var time=Stopwatch.StartNew();
        while(time.Elapsed.TotalSeconds<120)
        {
            Thread.Sleep(250);
            try
            {
                // User data is returned for display only, and cannot authorize a protected action.
                if(!File.Exists(record) || new FileInfo(record).Length>262144) continue;
                AssertNotLink(record);
                var read=new JavaScriptSerializer{MaxJsonLength=262144}.DeserializeObject(File.ReadAllText(record)) as IDictionary;
                if(read!=null && String.Equals(read["RequestId"] as string,id,StringComparison.Ordinal) &&
                    String.Equals(read["CountryCode"] as string,country,StringComparison.Ordinal) &&
                    String.Equals(read["ExpectedIpv4"] as string,ipv4,StringComparison.Ordinal)) return read;
            }
            catch(IOException){} catch(ArgumentException){}
        }
        throw new InvalidOperationException("未收到本次普通用户地区设置回执。");
    }
}
