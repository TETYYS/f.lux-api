using System;

namespace flux_api
{
    public class FLux {
        readonly Mem mem;
        
        public FLux(int ProcessID = 0) {
            mem = ProcessID != 0 ? new Mem(ProcessID) : new Mem("flux");

            mem.CheckProcess();
        }

        public void ScreenChanges(bool Enable)
        {
            if (Enable)
                mem.WriteByteArray(new IntPtr(0x45BE81), new byte[] { 0x8B, 0xF1, 0xE8, 0xE8, 0xE5, 0xFF, 0xFF });
            else
                mem.WriteByteArray(new IntPtr(0x45BE81), new byte[] { 0x5E, 0xC2, 0x04, 0x00, 0x90, 0x90, 0x90 });
        }
    }
}
