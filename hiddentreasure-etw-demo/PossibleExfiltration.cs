using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class PossibleExfiltration
    {
        static Dictionary<int, Dictionary<IPAddress, uint>> pidToDestination = new Dictionary<int, Dictionary<IPAddress, uint>>();

        private static Provider CreateNetworkProvider()
        {
            var filter = new EventFilter(
                Filter.EventIdIs(10) // IPv4 send
                .Or(Filter.EventIdIs(58))); // IPv6 send

            filter.OnEvent += (IEventRecord r) => {
                var daddr = r.GetIPAddress("daddr");
                var bytes = r.GetUInt32("size");
                var pid = (int)r.ProcessId;

                if (!pidToDestination.ContainsKey(pid)) pidToDestination[pid] = new Dictionary<IPAddress, uint>();
                if (!pidToDestination[pid].ContainsKey(daddr)) pidToDestination[pid][daddr] = 0;
                pidToDestination[pid][daddr] += bytes;
            };

            var provider = new Provider("Microsoft-Windows-Kernel-Network");
            provider.AddFilter(filter);

            return provider;
        }

        private static Provider CreateProcessProvider()
        {
            var filter = new EventFilter(
                Filter.EventIdIs(2)); // process end

            filter.OnEvent += (IEventRecord r) => {
                var pid = (int)r.ProcessId;

                if (pidToDestination.ContainsKey(pid))
                {
                    var destinationData = pidToDestination[pid];
                    pidToDestination.Remove(pid);

                    string processName = r.GetAnsiString("ImageName");

                    foreach (var destination in destinationData)
                    {
                        if (destination.Value < (1024 * 1024)) return; // 1MB threshold
                        Console.WriteLine($"{processName} (pid: {pid}) transferred "
                            + $"{destination.Value} bytes"
                            + $" to {destination.Key.ToString()}");
                    }
                }
            };

            var provider = new Provider("Microsoft-Windows-Kernel-Process");
            provider.AddFilter(filter);

            return provider;
        }

        public static UserTrace CreateTrace()
        {
            var networkProvider = CreateNetworkProvider();
            var processProvider = CreateProcessProvider();

            var trace = new UserTrace();
            trace.Enable(networkProvider);
            trace.Enable(processProvider);
            return trace;
        }
    }
}
