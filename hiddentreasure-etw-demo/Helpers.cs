using System;
using O365.Security.ETW;

namespace hiddentreasure_etw_demo
{
    public static class Helpers
    {
        public static void SetupCtrlC(UserTrace trace)
        {
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
        }
    }
}
