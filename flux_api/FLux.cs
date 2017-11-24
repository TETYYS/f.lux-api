using System;
using System.Runtime.InteropServices;

namespace flux_api
{
    public class FLux {

        [DllImport("flux_api_native.dll")]
        extern static uint InitializeFLuxApi(uint pid);

        [DllImport("flux_api_native.dll")]
        extern static uint EnableFLux();

        [DllImport("flux_api_native.dll")]
        extern static uint DisableFLux();

        class FLuxApiException : Exception
        {
            public FLuxApiException(string message) : base(message) { }
        }

        public FLux(uint ProcessID = 0) {
            uint ret;
            if ((ret = InitializeFLuxApi(ProcessID)) != 0)
                throw new FLuxApiException(String.Format("Native module returned 0x{0:X8}", ret));
        }

        public void ScreenChanges(bool Enable)
        {
            if (Enable)
                EnableFLux();
            else
                DisableFLux();
        }
    }
}
