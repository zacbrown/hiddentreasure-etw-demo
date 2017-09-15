using System;
using System.Diagnostics;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class PowerShellImageLoad
    {
        public static UserTrace CreateTrace()
        {
            // Unfortunately, this detection won't work for
            // processes that *already* have System.Management.Automation.dll
            // loaded into them. It does not check existing state, only activity
            // that occurs while the monitoring is enabled.
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
            return trace;
        }
    }
}
