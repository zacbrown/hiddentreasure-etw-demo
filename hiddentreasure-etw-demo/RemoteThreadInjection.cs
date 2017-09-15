using System;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class RemoteThreadInjection
    {
        public static UserTrace CreateTrace()
        {
            var filter = new EventFilter(Filter
                .EventIdIs(3));

            filter.OnEvent += (IEventRecord r) => {
                var sourcePID = r.ProcessId;
                var targetPID = r.GetUInt32("ProcessID");

                if (sourcePID != targetPID)
                {
                    var createdTID = r.GetUInt32("ThreadID");
                    var fmt = "Possible thread injection! - SourcePID: {0}, TargetPID: {1}, CreatedTID: {2}";
                    Console.WriteLine(fmt, sourcePID, targetPID, createdTID);
                }
            };

            var provider = new Provider("Microsoft-Windows-Kernel-Process");
            provider.AddFilter(filter);

            var trace = new UserTrace();
            trace.Enable(provider);
            return trace;
        }
    }
}
