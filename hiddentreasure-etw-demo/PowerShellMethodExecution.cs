// Copyright (c) Zac Brown. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class PowerShellMethodExecution
    {
        public static void Run()
        {
            // For a more thorough example of how to implement this detection,
            // have a look at https://github.com/zacbrown/PowerShellMethodAuditor
            var filter = new EventFilter(Filter
                .EventIdIs(7937)
                .And(UnicodeString.Contains("Payload", "Started"))
                .And(UnicodeString.Contains("ContextInfo", "Command Type = Function"))
                .And(UnicodeString.Contains("ContextInfo", "Command Name = prompt").op_LogicalNot())
                .And(UnicodeString.Contains("ContextInfo", "Command Name = PSConsoleHostReadline").op_LogicalNot()));

            filter.OnEvent += (IEventRecord r) => {
                var method = r.GetUnicodeString("ContextInfo");
                Console.WriteLine($"Method executed:\n{method}");
            };

            var provider = new Provider("Microsoft-Windows-PowerShell");
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
