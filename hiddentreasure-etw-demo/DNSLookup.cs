using System;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class DNSLookup
    {
        public static UserTrace CreateTrace()
        {
            var filter = new EventFilter(Filter
                .EventIdIs(3018) // cached lookup
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
            return trace;
        }
    }
}
