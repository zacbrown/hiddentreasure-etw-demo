// Copyright (c) Zac Brown. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class RemoteThreadInjection
    {
        public static void Run()
        {
            var filter = new EventFilter(Filter
                .EventIdIs(3));

            filter.OnEvent += (IEventRecord r) => {
                var sourcePID = r.ProcessId;
                var targetPID = r.GetUInt32("ProcessID");

                if (sourcePID != targetPID)
                {
                    // This is where you'd check that the target process's
                    // parent PID isn't the source PID. I've left it off for
                    // brevity since .NET doesn't provide an easy way to get
                    // parent PID :(.
                    var createdTID = r.GetUInt32("ThreadID");
                    var fmt = "Possible thread injection! - SourcePID: {0}, TargetPID: {1}, CreatedTID: {2}";
                    Console.WriteLine(fmt, sourcePID, targetPID, createdTID);
                }
            };

            var provider = new Provider("Microsoft-Windows-Kernel-Process");
            provider.AddFilter(filter);

            var trace = new UserTrace();
            trace.Enable(provider);

            // Setup Ctrl-C to call trace.Stop();
            Helpers.SetupCtrlC(trace);

            // This call is blocking. The thread that calls UserTrace.Start()
            // is donating itself to the ETW subsystem to pump events off
            // of the buffer.
            trace.Start();
        }
    }
}
