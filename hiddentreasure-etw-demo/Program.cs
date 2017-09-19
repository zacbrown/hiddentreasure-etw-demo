using System;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    class Program
    {
        static void Main(string[] args)
        {
            var trace = PresentChoice();

            // It's important that this comes before the
            // trace.Start() call below. The Start() call will
            // block the thread since it gets donated to ETW for
            // processing.
            Console.CancelKeyPress += (sender, eventArg) =>
            {
                if (trace != null)
                {
                    // Calling Stop on the trace is important
                    // because there are a limited number of trace
                    // sessions permitted on the OS. If you kill the
                    // program without calling Stop(), the trace session
                    // is left open and would need to be manually cleaned
                    // up.
                    //
                    // The easiest way to clean up the traces is to stop
                    // and delete them in the Computer Management>Performance
                    // section called "Event Trace Sessions".
                    //
                    // Alternatively, you can restart the machine.
                    trace.Stop();
                }
            };

            trace?.Start();
        }

        static UserTrace PresentChoice()
        {
            Console.WriteLine("Please select a scenario to run (enter a number):");
            Console.WriteLine("\t(1) Log DNS lookups on system");
            Console.WriteLine("\t(2) Log PowerShell function executions");
            Console.WriteLine("\t(3) Log PowerShell DLL loaded into processes");
            Console.WriteLine("\t(4) Log remote thread injections");
            Console.WriteLine("\t(5) Log possible data exfiltrations (over 1MB)");
            Console.Write("\nSelection: ");
            var strSelection = Console.ReadLine();

            int selection;
            if (int.TryParse(strSelection, out selection))
            {
                switch (selection)
                {
                    case 1:
                        Console.WriteLine("Logging DNS lookups...");
                        return DNSLookup.CreateTrace();
                    case 2:
                        Console.WriteLine("Logging PowerShell method executions...");
                        return PowerShellMethodExecution.CreateTrace();
                    case 3:
                        Console.WriteLine("Logging PowerShell DLL loads...");
                        return PowerShellImageLoad.CreateTrace();
                    case 4:
                        Console.WriteLine("Logging remote thread injections...");
                        return RemoteThreadInjection.CreateTrace();
                    case 5:
                        Console.WriteLine("Logging possible data exfiltrations (over 1MB)...");
                        return PossibleExfiltration.CreateTrace();
                }
            }

            Console.WriteLine("No selection made, exiting.");
            return null;
        }
    }
}