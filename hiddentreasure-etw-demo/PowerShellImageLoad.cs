using System;
using System.Diagnostics;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class PowerShellImageLoad
    {
        public static void Run()
        {
            var filter = new EventFilter(Filter
                .EventIdIs(5)
                .And(UnicodeString.IContains("ImageName", @"\System.Management.Automation.dll")));

            filter.OnEvent += (IEventRecord r) => {
                var pid = (int)r.ProcessId;
                var processName = Process.GetProcessById(pid).ProcessName;
                var imageName = r.GetUnicodeString("ImageName");
                Console.WriteLine($"{processName} (PID: {pid}) loaded {imageName}");
            };

            var provider = new Provider("Microsoft-Windows-Kernel-Process");
            provider.AddFilter(filter);

            var trace = new UserTrace();
            trace.Enable(provider);
            trace.Start();
        }
    }
}
