// Copyright (c) Zac Brown. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    class Program
    {
        static void Main(string[] args)
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
                        DNSLookup.Run();
                        return;
                    case 2:
                        Console.WriteLine("Logging PowerShell method executions...");
                        PowerShellMethodExecution.Run();
                        return;
                    case 3:
                        Console.WriteLine("Logging PowerShell DLL loads...");
                        PowerShellImageLoad.Run();
                        return;
                    case 4:
                        Console.WriteLine("Logging remote thread injections...");
                        RemoteThreadInjection.Run();
                        return;
                    case 5:
                        Console.WriteLine("Logging possible data exfiltrations (over 1MB)...");
                        PossibleExfiltration.Run();
                        return;
                    default:
                        Console.WriteLine($"No selection or invalid selection ({selection}) made, exiting.");
                        return;
                }
            }

            Console.WriteLine("Ctrl-C pressed, exiting.");
        }
    }
}