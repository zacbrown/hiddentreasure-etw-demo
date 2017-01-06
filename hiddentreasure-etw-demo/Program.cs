using System;
using O365.Security.ETW;
using System.Threading;

namespace hiddentreasure_etw_demo
{
    class Program
    {
        static void Main(string[] args)
        {
            var trace = new UserTrace();

            // The name of the PowerShell provider that gives us detailed
            // method execution logging is "Microsoft-Windows-PowerShell".
            var powershellProvider = new Provider("Microsoft-Windows-PowerShell");

            var powershellFilter = new EventFilter(Filter
                .EventIdIs(7937)
                .And(UnicodeString.Contains("Payload", "Started")));

            powershellFilter.OnEvent += OnEvent;

            // The "Any" and "All" flags vary from Provider to Provider.
            // You'll have to play with them in Microsoft Message Analyzer
            // or a similar tool to figure out what flags you need.
            powershellProvider.Any = 0x20;
            powershellProvider.AddFilter(powershellFilter);

            trace.Enable(powershellProvider);

            Console.CancelKeyPress += (sender, eventArg) =>
            {
                if (trace != null)
                {
                    Console.WriteLine("stopping ETW trace...");
                    Thread.Sleep(1000);
                    trace.Stop();
                }
            };

            Console.WriteLine("starting ETW trace...");

            // This is a blocking call. Ctrl-C to stop.
            trace.Start();
        }

        static void OnEvent(IEventRecord record)
        {
            string data = string.Empty;

            // The event property which contains the interesting information
            // in the PowerShell method invocation events is called "ContextInfo".
            // It's essentialy a giant well-formatted string blob.
            if (!record.TryGetUnicodeString("ContextInfo", out data))
            {
                Console.WriteLine("Could not parse 'ContextInfo' from PowerShell event");
                return;
            }

            if (data.IndexOf("invoke-mimikatz", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Console.WriteLine($"BAD METHOD!");
                Console.WriteLine(data);
            }
        }
    }
}
