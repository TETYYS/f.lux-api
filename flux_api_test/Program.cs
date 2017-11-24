using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace flux_api_test
{
    class Program
    {
        static void Main(string[] args)
        {
            var flux = new flux_api.FLux();
            while (true) {
                if (Process.GetProcessesByName("game").Length != 0)
                    flux.ScreenChanges(false);
                else
                    flux.ScreenChanges(true);

                Thread.Sleep(5000);
            }
        }
    }
}
