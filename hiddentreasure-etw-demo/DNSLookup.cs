// Copyright (c) Zac Brown. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class DNSLookup
    {
        public static void Run()
        {
            var filter = new EventFilter(
                Filter.EventIdIs(3018) // cached lookup
                .Or(Filter.EventIdIs(3020))); // live lookup

            filter.OnEvent += (IEventRecord r) => {
                var query = r.GetUnicodeString("QueryName");
                var result = r.GetUnicodeString("QueryResults");
                Console.WriteLine($"DNS query ({r.Id}): {query} - {result}");
            };

            var provider = new Provider("Microsoft-Windows-DNS-Client");
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
