using System;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class PowerShellMethodExecution
    {
        public static UserTrace CreateTrace()
        {
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
            return trace;
        }
    }
}
