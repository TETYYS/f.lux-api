using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace flux_api
{
    class Mem
    {
        private IntPtr baseAddress;
        public bool debugMode;
        public Process mainProcess;
        private IntPtr processHandle;
        private ProcessModule processModule;
        public long getBaseAddress
        {
            get
            {
                baseAddress = IntPtr.Zero;
                processModule = mainProcess.MainModule;
                baseAddress = processModule.BaseAddress;
                return (long)baseAddress;
            }
        }

        public string processName;
        public int processPid;

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, uint lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, uint lpNumberOfBytesWritten);

        public Mem(string pProcessName)
        {
            processName = pProcessName;
        }

        public Mem(int pPid)
        {
            processPid = pPid;
        }

        public bool CheckProcess()
        {
            if (processName != null)
            {
                Process[] p = Process.GetProcessesByName(processName);
                if (p.Length == 0)
                    return false;
                mainProcess = p[0];
                try {
                    processHandle = mainProcess.Handle;
                } catch {
                    return false;
                }
                return mainProcess != null;
            } else if (processPid != 0) {
                try {
                    var p = Process.GetProcessById(processPid);
                    mainProcess = p;
                    try
                    {
                        processHandle = mainProcess.Handle;
                    }
                    catch
                    {
                        return false;
                    }
                    return true;
                } catch {
                    return false;
                }
            }
            return false;
        }

        public byte ReadByte(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
                return 0;
            }
            try
            {
                return ReadByteArray(pOffset, 1)[0];
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadByte: " + e);
                }
                return 0;
            }
        }

        public byte[] ReadByteArray(IntPtr pOffset, uint pSize)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                uint num;
                VirtualProtectEx(processHandle, pOffset, (UIntPtr)pSize, 4, out num);
                var lpBuffer = new byte[pSize];
                ReadProcessMemory(processHandle, pOffset, lpBuffer, pSize, 0);
                VirtualProtectEx(processHandle, pOffset, (UIntPtr)pSize, num, out num);
                return lpBuffer;
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadByteArray: " + e);
                }
                return null;
            }
        }

        public bool ReadBoolean(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToBoolean(ReadByteArray(pOffset, 1), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadByte: " + e);
                }
                return false;
            }
        }

        public char ReadChar(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToChar(ReadByteArray(pOffset, 1), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadChar: " + e);
                }
                return Char.MinValue;
            }
        }

        public double ReadDouble(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToDouble(ReadByteArray(pOffset, 8), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadDouble: " + e);
                }
                return 0;
            }
        }

        public float ReadFloat(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToSingle(ReadByteArray(pOffset, 4), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadFloat: " + e);
                }
                return 0;
            }
        }

        public short ReadInt16(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToInt16(ReadByteArray(pOffset, 2), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadInt16: " + e);
                }
                return 0;
            }
        }

        public int ReadInt32(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToInt32(ReadByteArray(pOffset, 4), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadInt32: " + e);
                }
                return 0;
            }
        }

        public long ReadInt64(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToInt64(ReadByteArray(pOffset, 8), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadInt64: " + e);
                }
                return 0;
            }
        }

        /*
		*
		*
		*
		*
		*
		* */

        public string ReadStringASCII(IntPtr pOffset, uint pSize)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return Encoding.ASCII.GetString(ReadByteArray(pOffset, pSize), 0, (int)pSize);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadStringASCII: " + e);
                }
                return null;
            }
        }

        public string ReadStringUnicode(IntPtr pOffset, uint pSize)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return Encoding.Unicode.GetString(ReadByteArray(pOffset, pSize), 0, (int)pSize);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadStringUnicode: " + e);
                }
                return null;
            }
        }

        public ushort ReadUInt16(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToUInt16(ReadByteArray(pOffset, 2), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadUInt16: " + e);
                }
                return 0;
            }
        }

        public uint ReadUInt32(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToUInt32(ReadByteArray(pOffset, 4), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadUInt32: " + e);
                }
                return 0;
            }
        }

        public ulong ReadUInt64(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToUInt64(ReadByteArray(pOffset, 8), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadUInt64: " + e);
                }
                return 0;
            }
        }

        public uint ReadUInteger(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToUInt32(ReadByteArray(pOffset, 4), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadUInteger: " + e);
                }
                return 0;
            }
        }

        public long ReadULong(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return (long)BitConverter.ToUInt64(ReadByteArray(pOffset, 8), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadULong: " + e);
                }
                return 0;
            }
        }

        public ushort ReadUShort(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return BitConverter.ToUInt16(ReadByteArray(pOffset, 2), 0);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadUShort: " + e);
                }
                return 0;
            }
        }

        public DWORD ReadDWORD(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return new DWORD(ReadByteArray(pOffset, 4));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadUShort: " + e);
                }
                return null;
            }
        }

        public WORD ReadWORD(IntPtr pOffset)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return new WORD(ReadByteArray(pOffset, 2));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadUShort: " + e);
                }
                return null;
            }
        }

        const int BLOCK_SIZE = 4096;
        public IntPtr SearchPattern(IntPtr Start, int Length, byte[] In, string Pattern)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }

            int matchCount = 0;

            try
            {
                var blocks = (int)Math.Ceiling((double)Length / BLOCK_SIZE);
                for (int x = 0; x < blocks; x++)
                {
                    var block = BLOCK_SIZE;
                    if (x == blocks)
                    {
                        block = Length % BLOCK_SIZE;
                    }

                    var mem = ReadByteArray((IntPtr)((int)Start + (x * BLOCK_SIZE)), (uint)block);

                    for (int i = 0; i < mem.Length; i++)
                    {
                        if (Pattern[matchCount] != '?')
                        {
                            if (mem[i] == In[matchCount])
                                matchCount++;
                            else
                                matchCount = 0;
                        }
                        else
                            matchCount++;

                        if (matchCount == In.Length)
                            return (IntPtr)((int)Start + (x * BLOCK_SIZE) + i - matchCount + 1);
                    }
                }
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: ReadUShort: " + e);
                }
                return IntPtr.Zero;
            }
            return IntPtr.Zero;
        }

        /*
	 *
	 *
	 *
	 */

        public bool WriteBit(IntPtr pOffset, byte BitPos, bool Value)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                byte val = ReadByte(pOffset);
                if (Value)
                    val |= (byte)(1 << BitPos);
                else
                    val &= (byte)~(1 << BitPos);

                return WriteByte(pOffset, val);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteByte: " + e);
                }
                return false;
            }
        }

        public bool WriteBits(IntPtr pOffset, byte[] BitPos, bool[] Value)
        {
            Debug.Assert(BitPos.Length == Value.Length);

            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                byte val = ReadByte(pOffset);
                for (int x = 0; x < BitPos.Length; x++)
                {
                    if (Value[x])
                        val |= (byte)(1 << BitPos[x]);
                    else
                        val &= (byte)~(1 << BitPos[x]);
                }

                return WriteByte(pOffset, val);
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteByte: " + e);
                }
                return false;
            }
        }

        public bool WriteByte(IntPtr pOffset, byte pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteByte: " + e);
                }
                return false;
            }
        }

        public bool WriteByteArray(IntPtr pOffset, byte[] pBytes)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                uint num;
                VirtualProtectEx(processHandle, pOffset, (UIntPtr)pBytes.Length, 4, out num);
                bool flag = WriteProcessMemory(processHandle, pOffset, pBytes, (uint)pBytes.Length, 0);
                VirtualProtectEx(processHandle, pOffset, (UIntPtr)pBytes.Length, num, out num);
                if (Marshal.GetLastWin32Error() != 0)
                {
                    throw new Win32Exception(new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
                return flag;
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteByteArray: " + e);
                }
                return false;
            }
        }

        public bool WriteBoolean(IntPtr pOffset, bool pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteBoolean: " + e);
                }
                return false;
            }
        }

        public bool WriteChar(IntPtr pOffset, char pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteChar: " + e);
                }
                return false;
            }
        }

        public bool WriteDouble(IntPtr pOffset, double pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteDouble: " + e);
                }
                return false;
            }
        }

        public bool WriteFloat(IntPtr pOffset, float pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteFloat: " + e);
                }
                return false;
            }
        }

        public bool WriteInt16(IntPtr pOffset, short pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteInt16: " + e);
                }
                return false;
            }
        }

        public bool WriteInt32(IntPtr pOffset, int pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteInt32: " + e);
                }
                return false;
            }
        }

        public bool WriteInt64(IntPtr pOffset, long pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteInt64: " + e);
                }
                return false;
            }
        }

        public bool WriteInteger(IntPtr pOffset, int pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteInt: " + e);
                }
                return false;
            }
        }

        public bool WriteLong(IntPtr pOffset, long pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteLong: " + e);
                }
                return false;
            }
        }

        public bool WriteShort(IntPtr pOffset, short pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteShort: " + e);
                }
                return false;
            }
        }

        public bool WriteStringASCII(IntPtr pOffset, string pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, Encoding.ASCII.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteStringASCII: " + e);
                }
                return false;
            }
        }

        public bool WriteStringUnicode(IntPtr pOffset, string pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, Encoding.Unicode.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteStringUnicode: " + e);
                }
                return false;
            }
        }

        public bool WriteUInt16(IntPtr pOffset, ushort pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteUInt16: " + e);
                }
                return false;
            }
        }

        public bool WriteUInt32(IntPtr pOffset, uint pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteUInt32: " + e);
                }
                return false;
            }
        }

        public bool WriteUInt64(IntPtr pOffset, ulong pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteUInt64: " + e);
                }
                return false;
            }
        }

        public bool WriteUInteger(IntPtr pOffset, uint pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteUInt: " + e);
                }
                return false;
            }
        }

        public bool WriteULong(IntPtr pOffset, ulong pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteULong: " + e);
                }
                return false;
            }
        }

        public bool WriteUShort(IntPtr pOffset, ushort pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, BitConverter.GetBytes(pData));
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteShort: " + e);
                }
                return false;
            }
        }

        public bool WriteDWORD(IntPtr pOffset, DWORD pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, pData.ToByteArray());
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteDWORD: " + e);
                }
                return false;
            }
        }

        public bool WriteWORD(IntPtr pOffset, WORD pData)
        {
            if (processHandle == IntPtr.Zero)
            {
                CheckProcess();
            }
            try
            {
                return WriteByteArray(pOffset, pData.ToByteArray());
            }
            catch (Exception e)
            {
                if (debugMode)
                {
                    Console.WriteLine("Error: WriteWORD: " + e);
                }
                return false;
            }
        }

        /// <summary>
        /// Finds address of pointer and offset
        /// </summary>
        /// <param name="pointer">Pointer</param>
        /// <param name="offset">Offset of pointer</param>
        /// <returns>Actual address</returns>
        public IntPtr PtrToAddr(IntPtr pointer, int offset)
        {
            ulong result = 0;
            byte[] rd = ReadByteArray(pointer, 4);
            for (int x = 0, pos = 0; x < rd.Length; x++)
            {
                result |= ((ulong)rd[x] << pos);
                pos += 8;
            }
            return new IntPtr((int)result + offset);
        }

        /// <summary>
        /// Finds address of multilevel pointer
        /// </summary>
        /// <param name="pointer">Base pointer</param>
        /// <param name="offsets">Offsets</param>
        /// <returns>Actual address</returns>
        public IntPtr multiLvlPtrToAddr(IntPtr pointer, params int[] offsets)
        {
            IntPtr ret = IntPtr.Zero;
            for (int x = 0; x < offsets.Length; x++)
            {
                ret = PtrToAddr(x == 0 ? pointer : ret, offsets[x]);
            }
            return ret;
        }
    }

    public class DWORD
    {
        private byte[] Dw;

        public DWORD(byte[] val)
        {
            if (val.Length < 4)
                Dw = val;
            else
            {
                throw new InvalidOperationException("Byte array cannot exceed 4 bytes");
            }
        }

        public static implicit operator DWORD(byte[] val)
        {
            return new DWORD(val);
        }

        public static implicit operator byte[] (DWORD DW)
        {
            return DW.Dw;
        }

        public byte[] ToByteArray()
        {
            return Dw;
        }
    }

    public class WORD
    {
        private byte[] W;

        public WORD(byte[] val)
        {
            if (val.Length < 2)
                W = val;
            else
            {
                throw new InvalidOperationException("Byte array cannot exceed 2 bytes");
            }
        }

        public static implicit operator WORD(byte[] val)
        {
            return new WORD(val);
        }

        public static implicit operator byte[] (WORD w)
        {
            return w.W;
        }

        public byte[] ToByteArray()
        {
            return W;
        }
    }
}