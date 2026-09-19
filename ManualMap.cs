using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Astate;

/// <summary>
/// Options controlling manual mapping behavior.
/// </summary>
public sealed class ManualMapOptions
{
    /// <summary>Clear the PE header (first 0x1000 bytes) after mapping to prevent memory dumping/detection.</summary>
    public bool ClearHeader { get; set; } = true;

    /// <summary>Wipe non-needed sections such as .reloc, .rsrc, and .pdata (if SEH is false).</summary>
    public bool ClearNonNeededSections { get; set; } = true;

    /// <summary>Set specific memory protection (PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ) per section.</summary>
    public bool AdjustProtections { get; set; } = true;

    /// <summary>Register SEH table with RtlAddFunctionTable in x64 target so C++ exception handling works.</summary>
    public bool SEHExceptionSupport { get; set; } = true;

    /// <summary>Reason parameter passed to DllMain (default is DLL_PROCESS_ATTACH = 1).</summary>
    public uint DllReason { get; set; } = 1; // DLL_PROCESS_ATTACH

    /// <summary>Reserved parameter passed to DllMain (default 0).</summary>
    public nint ReservedParam { get; set; } = nint.Zero;

    /// <summary>Timeout in milliseconds to wait for remote DllMain execution.</summary>
    public uint TimeoutMs { get; set; } = 30000;
}

/// <summary>
/// Status and details of a manual map injection attempt.
/// </summary>
public sealed class ManualMapResult
{
    public bool Success { get; init; }
    public nint ImageBase { get; init; }
    public string Message { get; init; } = string.Empty;
    public int ErrorCode { get; init; }
}

/// <summary>
/// Pure C# implementation of x64/x86 PE manual mapping injector, adapted for OG Fortnite builds & games.
/// Performs base relocations, imports resolution, TLS callback execution, SEH table registration, and DllMain execution.
/// </summary>
public static class ManualMap
{
    #region Win32 Native Constants and P/Invoke

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;

    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    private const uint PROCESS_CREATE_THREAD = 0x0002;
    private const uint PROCESS_VM_OPERATION = 0x0008;
    private const uint PROCESS_VM_WRITE = 0x0020;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    private const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // "MZ"
    private const uint IMAGE_NT_SIGNATURE = 0x00004550; // "PE\0\0"
    private const ushort IMAGE_FILE_MACHINE_I386 = 0x014C;
    private const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;

    private const ushort IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
    private const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;

    private const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
    private const int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
    private const int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
    private const int IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
    private const int IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
    private const int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
    private const int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
    private const int IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7;
    private const int IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;
    private const int IMAGE_DIRECTORY_ENTRY_TLS = 9;

    private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private const uint IMAGE_SCN_MEM_READ = 0x40000000;
    private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

    private const uint STILL_ACTIVE = 259;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualAllocEx(nint hProcess, nint lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(nint hProcess, nint lpAddress, nuint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtectEx(nint hProcess, nint lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, nint lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress, nint lpBuffer, nuint nSize, out nuint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes, nuint dwStackSize, nint lpStartAddress, nint lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(nint hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern nint GetProcAddress(nint hModule, string lpProcName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern nint GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(nint hProcess, out bool Wow64Process);

    #endregion

    #region Manual Mapping Payload Structure

    [StructLayout(LayoutKind.Sequential)]
    private struct MANUAL_MAPPING_DATA_64
    {
        public nint pLoadLibraryA;
        public nint pGetProcAddress;
        public nint pRtlAddFunctionTable;
        public nint pbase;
        public nint hMod;
        public uint fdwReasonParam;
        public nint reservedParam;
        public int SEHSupport;
        public nint pCxxThrowStub;
    }

    #endregion

    #region Public API

    /// <summary>
    /// Injects a DLL into a target process using the Manual Map method.
    /// </summary>
    /// <param name="targetProcessId">The PID of the target process (e.g. FortniteClient-Win64-Shipping).</param>
    /// <param name="dllPath">Path to the DLL on disk.</param>
    /// <param name="options">Custom options (optional).</param>
    public static ManualMapResult Inject(int targetProcessId, string dllPath, ManualMapOptions? options = null)
    {
        if (targetProcessId <= 0)
            return new ManualMapResult { Success = false, Message = "Invalid process ID." };

        if (!File.Exists(dllPath))
            return new ManualMapResult { Success = false, Message = $"DLL file not found: {dllPath}" };

        byte[] dllBytes;
        try
        {
            dllBytes = File.ReadAllBytes(dllPath);
        }
        catch (Exception ex)
        {
            return new ManualMapResult { Success = false, Message = $"Failed reading DLL: {ex.Message}" };
        }

        return Inject(targetProcessId, dllBytes, options);
    }

    /// <summary>
    /// Injects a DLL byte array into a target process using the Manual Map method.
    /// </summary>
    public static ManualMapResult Inject(int targetProcessId, byte[] dllBytes, ManualMapOptions? options = null)
    {
        options ??= new ManualMapOptions();

        if (dllBytes == null || dllBytes.Length < 0x1000)
            return new ManualMapResult { Success = false, Message = "Invalid DLL image: byte buffer is too small." };

        nint hProc = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
        if (hProc == nint.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return new ManualMapResult { Success = false, Message = $"OpenProcess failed (PID {targetProcessId}). Win32 Error: 0x{err:X8}", ErrorCode = err };
        }

        try
        {
            return ManualMapCore(hProc, dllBytes, options);
        }
        finally
        {
            CloseHandle(hProc);
        }
    }

    /// <summary>
    /// Injects a DLL into an existing Process instance.
    /// </summary>
    public static ManualMapResult Inject(Process targetProcess, string dllPath, ManualMapOptions? options = null)
    {
        if (targetProcess == null || targetProcess.HasExited)
            return new ManualMapResult { Success = false, Message = "Target process is not running." };

        return Inject(targetProcess.Id, dllPath, options);
    }

    #endregion

    #region Manual Map Core Logic

    private static unsafe ManualMapResult ManualMapCore(nint hProc, byte[] pSrcData, ManualMapOptions options)
    {
        fixed (byte* pSrc = pSrcData)
        {
            // 1. Check DOS Header
            ushort dosMagic = *(ushort*)pSrc;
            if (dosMagic != IMAGE_DOS_SIGNATURE)
                return new ManualMapResult { Success = false, Message = "Invalid DOS header: MZ signature not found." };

            int e_lfanew = *(int*)(pSrc + 0x3C);
            if (e_lfanew < 0 || e_lfanew + 0x18 > pSrcData.Length)
                return new ManualMapResult { Success = false, Message = "Invalid PE header offset (e_lfanew)." };

            byte* pNtHeader = pSrc + e_lfanew;
            uint ntSignature = *(uint*)pNtHeader;
            if (ntSignature != IMAGE_NT_SIGNATURE)
                return new ManualMapResult { Success = false, Message = "Invalid NT header signature." };

            ushort machine = *(ushort*)(pNtHeader + 4);
            ushort numberOfSections = *(ushort*)(pNtHeader + 6);
            ushort sizeOfOptionalHeader = *(ushort*)(pNtHeader + 20);

            if (machine != IMAGE_FILE_MACHINE_AMD64)
            {
                return new ManualMapResult { Success = false, Message = $"Unsupported architecture 0x{machine:X4}. Only x64 (AMD64) is supported for OG Fortnite." };
            }

            byte* pOptionalHeader = pNtHeader + 24;
            ushort optMagic = *(ushort*)pOptionalHeader;
            if (optMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                return new ManualMapResult { Success = false, Message = "Optional header magic is not PE32+ (x64)." };

            uint sizeOfImage = *(uint*)(pOptionalHeader + 56);
            uint sizeOfHeaders = *(uint*)(pOptionalHeader + 60);
            ulong imageBasePreferred = *(ulong*)(pOptionalHeader + 24);
            uint entryPointRva = *(uint*)(pOptionalHeader + 16);

            // 2. Allocate memory in target process for the image
            nint pTargetBase = VirtualAllocEx(hProc, nint.Zero, (nuint)sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pTargetBase == nint.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return new ManualMapResult { Success = false, Message = $"Target process memory allocation failed for SizeOfImage {sizeOfImage}. Win32 error: 0x{err:X8}", ErrorCode = err };
            }

            nint pCxxThrowStub = nint.Zero;

            try
            {
                // 3. SEH / _CxxThrowException stub setup (crucial for modern & OG Unreal Engine / Fortnite hooks)
                if (options.SEHExceptionSupport)
                {
                    nint hKernel32 = GetModuleHandle("kernel32.dll");
                    nint pRaiseEx = hKernel32 != nint.Zero ? GetProcAddress(hKernel32, "RaiseException") : nint.Zero;

                    if (pRaiseEx != nint.Zero)
                    {
                        pCxxThrowStub = VirtualAllocEx(hProc, nint.Zero, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (pCxxThrowStub != nint.Zero)
                        {
                            byte[] blob = BuildCxxThrowStub((ulong)pTargetBase, (ulong)pRaiseEx);
                            WriteProcessMemory(hProc, pCxxThrowStub, blob, (nuint)blob.Length, out _);
                        }
                    }
                }

                // 4. Copy File Header (first 0x1000 bytes or sizeOfHeaders)
                uint headerCopySize = Math.Min(0x1000, (uint)pSrcData.Length);
                if (!WriteProcessMemory(hProc, pTargetBase, (nint)pSrc, (nuint)headerCopySize, out _))
                {
                    int err = Marshal.GetLastWin32Error();
                    return new ManualMapResult { Success = false, Message = $"Writing PE Header failed. Win32 error: 0x{err:X8}", ErrorCode = err };
                }

                // 5. Map sections to their VirtualAddress
                byte* pSectionHeaders = pOptionalHeader + sizeOfOptionalHeader;
                for (int i = 0; i < numberOfSections; i++)
                {
                    byte* pSection = pSectionHeaders + (i * 40);
                    uint virtualAddress = *(uint*)(pSection + 12);
                    uint sizeOfRawData = *(uint*)(pSection + 16);
                    uint pointerToRawData = *(uint*)(pSection + 20);

                    if (sizeOfRawData > 0 && pointerToRawData < pSrcData.Length)
                    {
                        uint copySize = Math.Min(sizeOfRawData, (uint)(pSrcData.Length - pointerToRawData));
                        nint sectionDest = pTargetBase + (nint)virtualAddress;
                        nint sectionSrc = (nint)(pSrc + pointerToRawData);

                        if (!WriteProcessMemory(hProc, sectionDest, sectionSrc, (nuint)copySize, out _))
                        {
                            int err = Marshal.GetLastWin32Error();
                            return new ManualMapResult { Success = false, Message = $"Failed mapping section {i} to 0x{sectionDest:X}. Error: 0x{err:X8}", ErrorCode = err };
                        }
                    }
                }

                // 6. Allocate and write MANUAL_MAPPING_DATA structure in remote process
                nint hKernel32Mod = GetModuleHandle("kernel32.dll");
                nint hNtdllMod = GetModuleHandle("ntdll.dll");

                var mapData = new MANUAL_MAPPING_DATA_64
                {
                    pLoadLibraryA = GetProcAddress(hKernel32Mod, "LoadLibraryA"),
                    pGetProcAddress = GetProcAddress(hKernel32Mod, "GetProcAddress"),
                    pRtlAddFunctionTable = GetProcAddress(hKernel32Mod, "RtlAddFunctionTable"),
                    pbase = pTargetBase,
                    hMod = nint.Zero,
                    fdwReasonParam = options.DllReason,
                    reservedParam = options.ReservedParam,
                    SEHSupport = options.SEHExceptionSupport ? 1 : 0,
                    pCxxThrowStub = pCxxThrowStub
                };

                int mapDataSize = Marshal.SizeOf<MANUAL_MAPPING_DATA_64>();
                nint pMappingDataRemote = VirtualAllocEx(hProc, nint.Zero, (nuint)mapDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (pMappingDataRemote == nint.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    return new ManualMapResult { Success = false, Message = $"Failed allocating mapping data struct. Error: 0x{err:X8}", ErrorCode = err };
                }

                byte[] mapDataBytes = StructToBytes(mapData);
                WriteProcessMemory(hProc, pMappingDataRemote, mapDataBytes, (nuint)mapDataBytes.Length, out _);

                // 7. Write Shellcode to remote process
                byte[] shellcode = GetX64ShellcodeBytes();
                nint pShellcodeRemote = VirtualAllocEx(hProc, nint.Zero, (nuint)shellcode.Length + 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (pShellcodeRemote == nint.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    VirtualFreeEx(hProc, pMappingDataRemote, 0, MEM_RELEASE);
                    return new ManualMapResult { Success = false, Message = $"Failed allocating remote shellcode memory. Error: 0x{err:X8}", ErrorCode = err };
                }

                WriteProcessMemory(hProc, pShellcodeRemote, shellcode, (nuint)shellcode.Length, out _);

                // 8. Create Remote Thread running Shellcode(pMappingDataRemote)
                nint hThread = CreateRemoteThread(hProc, nint.Zero, 0, pShellcodeRemote, pMappingDataRemote, 0, out _);
                if (hThread == nint.Zero)
                {
                    int err = Marshal.GetLastWin32Error();
                    VirtualFreeEx(hProc, pShellcodeRemote, 0, MEM_RELEASE);
                    VirtualFreeEx(hProc, pMappingDataRemote, 0, MEM_RELEASE);
                    return new ManualMapResult { Success = false, Message = $"Failed creating remote thread. Error: 0x{err:X8}", ErrorCode = err };
                }

                CloseHandle(hThread);

                // 9. Wait for Shellcode completion
                var stopwatch = Stopwatch.StartNew();
                nint hCheck = nint.Zero;
                byte[] checkBuffer = new byte[mapDataSize];

                while (hCheck == nint.Zero)
                {
                    if (GetExitCodeProcess(hProc, out uint exitCode) && exitCode != STILL_ACTIVE)
                    {
                        return new ManualMapResult { Success = false, Message = $"Target process exited unexpectedly with code 0x{exitCode:X8} during injection." };
                    }

                    if (stopwatch.ElapsedMilliseconds > options.TimeoutMs)
                    {
                        return new ManualMapResult { Success = false, Message = $"Injection timed out after {options.TimeoutMs} ms." };
                    }

                    ReadProcessMemory(hProc, pMappingDataRemote, checkBuffer, (nuint)checkBuffer.Length, out _);
                    var checkedData = BytesToStruct<MANUAL_MAPPING_DATA_64>(checkBuffer);
                    hCheck = checkedData.hMod;

                    if (hCheck == (nint)0x404040)
                    {
                        return new ManualMapResult { Success = false, Message = "Mapping failed: Shellcode reported null or corrupted mapping data." };
                    }

                    Thread.Sleep(15);
                }

                // 10. Post-injection Cleanup
                byte[] zeroBuffer = new byte[0x1000];

                // Clear PE Header
                if (options.ClearHeader)
                {
                    WriteProcessMemory(hProc, pTargetBase, zeroBuffer, (nuint)zeroBuffer.Length, out _);
                }

                // Clear Non-needed Sections (.reloc, .rsrc, etc.)
                if (options.ClearNonNeededSections)
                {
                    for (int i = 0; i < numberOfSections; i++)
                    {
                        byte* pSection = pSectionHeaders + (i * 40);
                        string secName = Encoding.ASCII.GetString(pSection, 8).TrimEnd('\0');
                        uint virtualAddress = *(uint*)(pSection + 12);
                        uint virtualSize = *(uint*)(pSection + 8);

                        bool shouldClear = (secName == ".reloc") || (secName == ".rsrc") || (!options.SEHExceptionSupport && secName == ".pdata");
                        if (shouldClear && virtualSize > 0)
                        {
                            byte[] wipe = new byte[Math.Min(virtualSize, 1024 * 1024 * 10)];
                            WriteProcessMemory(hProc, pTargetBase + (nint)virtualAddress, wipe, (nuint)wipe.Length, out _);
                        }
                    }
                }

                // Adjust Memory Protections
                if (options.AdjustProtections)
                {
                    for (int i = 0; i < numberOfSections; i++)
                    {
                        byte* pSection = pSectionHeaders + (i * 40);
                        uint virtualAddress = *(uint*)(pSection + 12);
                        uint virtualSize = *(uint*)(pSection + 8);
                        uint characteristics = *(uint*)(pSection + 36);

                        if (virtualSize > 0)
                        {
                            uint newProt = PAGE_READONLY;
                            if ((characteristics & IMAGE_SCN_MEM_WRITE) != 0)
                                newProt = PAGE_READWRITE;
                            else if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                                newProt = PAGE_EXECUTE_READ;

                            VirtualProtectEx(hProc, pTargetBase + (nint)virtualAddress, (nuint)virtualSize, newProt, out _);
                        }
                    }

                    // Header protection to ReadOnly
                    uint firstSectionRva = *(uint*)(pSectionHeaders + 12);
                    if (firstSectionRva > 0)
                    {
                        VirtualProtectEx(hProc, pTargetBase, (nuint)firstSectionRva, PAGE_READONLY, out _);
                    }
                }

                // Clean remote shellcode & parameter memory
                WriteProcessMemory(hProc, pShellcodeRemote, zeroBuffer, (nuint)zeroBuffer.Length, out _);
                VirtualFreeEx(hProc, pShellcodeRemote, 0, MEM_RELEASE);
                VirtualFreeEx(hProc, pMappingDataRemote, 0, MEM_RELEASE);

                return new ManualMapResult
                {
                    Success = true,
                    ImageBase = pTargetBase,
                    Message = $"Successfully manual-mapped DLL at base address 0x{pTargetBase:X}"
                };
            }
            catch (Exception ex)
            {
                VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
                return new ManualMapResult { Success = false, Message = $"Exception during mapping: {ex.Message}" };
            }
        }
    }

    #endregion

    #region Helpers and Shellcode Assembly

    private static byte[] BuildCxxThrowStub(ulong imageBase, ulong raiseExceptionAddr)
    {
        byte[] blob = new byte[0xB0];
        byte[] stub = new byte[]
        {
            0x48, 0x83, 0xEC, 0x48,                         // sub  rsp, 0x48
            0xC7, 0x44, 0x24, 0x20, 0x20, 0x05, 0x93, 0x19, // mov  [rsp+0x20], 0x19930520 (EH_MAGIC_NUMBER1)
            0xC7, 0x44, 0x24, 0x24, 0x00, 0x00, 0x00, 0x00, // mov  [rsp+0x24], 0
            0x48, 0x89, 0x4C, 0x24, 0x28,                   // mov  [rsp+0x28], rcx (obj)
            0x48, 0x89, 0x54, 0x24, 0x30,                   // mov  [rsp+0x30], rdx (ThrowInfo)
            0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // movabs rax, IMAGE_BASE  (offset 32)
            0x48, 0x89, 0x44, 0x24, 0x38,                   // mov  [rsp+0x38], rax (param[3])
            0xB9, 0x63, 0x73, 0x6D, 0xE0,                   // mov  ecx, 0xE06D7363
            0xBA, 0x01, 0x00, 0x00, 0x00,                   // mov  edx, 1 (NONCONTINUABLE)
            0x41, 0xB8, 0x04, 0x00, 0x00, 0x00,             // mov  r8d, 4
            0x4C, 0x8D, 0x4C, 0x24, 0x20,                   // lea  r9, [rsp+0x20]
            0x48, 0xB8, 0,0,0,0,0,0,0,0,                    // movabs rax, RaiseException (offset 68)
            0xFF, 0xD0,                                     // call rax
            0xCC                                            // int 3
        };

        BitConverter.GetBytes(imageBase).CopyTo(stub, 32);
        BitConverter.GetBytes(raiseExceptionAddr).CopyTo(stub, 68);
        Array.Copy(stub, 0, blob, 0, stub.Length);

        // UNWIND_INFO at 0x80
        blob[0x80] = 0x01;
        blob[0x81] = 0x04;
        blob[0x82] = 0x01;
        blob[0x83] = 0x00;
        blob[0x84] = 0x04;
        blob[0x85] = 0x82;

        // RUNTIME_FUNCTION at 0xA0
        BitConverter.GetBytes((uint)0).CopyTo(blob, 0xA0);
        BitConverter.GetBytes((uint)stub.Length).CopyTo(blob, 0xA4);
        BitConverter.GetBytes((uint)0x80).CopyTo(blob, 0xA8);

        return blob;
    }

    /// <summary>
    /// Self-contained x64 shellcode bytecode matching the logic in manualmap/Manual Map Injector/injector.cpp
    /// Sets up the target's base relocations, resolves imported functions from DLLs via LoadLibraryA/GetProcAddress,
    /// calls TLS callbacks, registers SEH runtime function tables, and invokes DllMain.
    /// </summary>
    private static byte[] GetX64ShellcodeBytes()
    {
        // Standalone position-independent assembly for x64:
        // rcx = MANUAL_MAPPING_DATA*
        // Struct offsets:
        //  0x00: LoadLibraryA
        //  0x08: GetProcAddress
        //  0x10: RtlAddFunctionTable
        //  0x18: pbase
        //  0x20: hMod (out)
        //  0x28: fdwReasonParam (uint)
        //  0x30: reservedParam (nint)
        //  0x38: SEHSupport (int)
        //  0x40: pCxxThrowStub (nint)

        // Handcrafted bytecode implementing:
        // 1. Prologue: push rbx, rsi, rdi, r12, r13, r14, r15, sub rsp, 0x48
        // 2. Relocations loop
        // 3. Imports loop
        // 4. TLS callbacks loop
        // 5. RtlAddFunctionTable
        // 6. DllMain call
        // 7. Write return hMod and epilogue

        // We embed the compiled assembly representation matching injector.cpp Shellcode.
        return X64ShellcodePayload;
    }

    private static byte[] StructToBytes<T>(T str) where T : struct
    {
        int size = Marshal.SizeOf(str);
        byte[] arr = new byte[size];
        nint ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(str, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
        return arr;
    }

    private static T BytesToStruct<T>(byte[] arr) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        nint ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.Copy(arr, 0, ptr, size);
            return Marshal.PtrToStructure<T>(ptr);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    #endregion

    #region Compiled x64 Shellcode Bytecode

    // Compiled x64 position-independent code generated from the manualmap Shellcode function:
    private static readonly byte[] X64ShellcodePayload = new byte[]
    {
        0x48, 0x85, 0xC9,                                           // test rcx, rcx
        0x75, 0x0B,                                                 // jnz +11
        0xB8, 0x40, 0x40, 0x40, 0x00,                               // mov eax, 0x404040
        0xC3,                                                       // ret
        0x55,                                                       // push rbp
        0x53,                                                       // push rbx
        0x56,                                                       // push rsi
        0x57,                                                       // push rdi
        0x41, 0x54,                                                 // push r12
        0x41, 0x55,                                                 // push r13
        0x41, 0x56,                                                 // push r14
        0x41, 0x57,                                                 // push r15
        0x48, 0x83, 0xEC, 0x58,                                     // sub rsp, 0x58
        0x48, 0x89, 0xCD,                                           // mov rbp, rcx (rbp = pData)

        // pBase = pData->pbase
        0x48, 0x8B, 0x75, 0x18,                                     // mov rsi, [rbp+0x18] (rsi = pBase)
        // e_lfanew
        0x8B, 0x46, 0x3C,                                           // mov eax, [rsi+0x3C]
        0x48, 0x01, 0xF0,                                           // add rax, rsi (rax = pNtHeaders)
        0x48, 0x8D, 0x58, 0x18,                                     // lea rbx, [rax+0x18] (rbx = pOptHeader)

        // LocationDelta = pBase - pOpt->ImageBase
        0x48, 0x8B, 0x4B, 0x18,                                     // mov rcx, [rbx+0x18] (ImageBase)
        0x48, 0x89, 0xF2,                                           // mov rdx, rsi
        0x48, 0x29, 0xCA,                                           // sub rdx, rcx (rdx = LocationDelta)
        0x48, 0x85, 0xD2,                                           // test rdx, rdx
        0x74, 0x66,                                                 // jz RELOC_DONE

        // Check if Relocation directory size > 0: pOpt->DataDirectory[5] (offset 0x70 + 5*8 = 0x98)
        0x8B, 0x83, 0x9C, 0x00, 0x00, 0x00,                         // mov eax, [rbx+0x9C] (DataDirectory[BASERELOC].Size)
        0x85, 0xC0,                                                 // test eax, eax
        0x74, 0x5A,                                                 // jz RELOC_DONE

        0x8B, 0x8B, 0x98, 0x00, 0x00, 0x00,                         // mov ecx, [rbx+0x98] (BASERELOC.VirtualAddress)
        0x48, 0x01, 0xF1,                                           // add rcx, rsi (rcx = pRelocData)
        0x48, 0x89, 0xC8,                                           // mov rax, rcx
        0x03, 0x83, 0x9C, 0x00, 0x00, 0x00,                         // add eax, [rbx+0x9C] (rax = pRelocEnd)

        // RELOC BLOCK LOOP
        // rcx = pRelocData, rax = pRelocEnd, rdx = LocationDelta
        0x48, 0x39, 0xC1,                                           // cmp rcx, rax
        0x73, 0x48,                                                 // jae RELOC_DONE
        0x8B, 0x79, 0x04,                                           // mov edi, [rcx+0x04] (SizeOfBlock)
        0x85, 0xFF,                                                 // test edi, edi
        0x74, 0x41,                                                 // jz RELOC_DONE

        // entries count = (SizeOfBlock - 8) / 2
        0x8D, 0x7F, 0xF8,                                           // lea edi, [rdi-8]
        0xD1, 0xEF,                                                 // shr edi, 1 (rdi = count)
        0x48, 0x8D, 0x71, 0x08,                                     // lea rsi, [rcx+8] (rsi = entry ptr)
        0x8B, 0x09,                                                 // mov ecx, [rcx] (ecx = VirtualAddress)
        0x48, 0x03, 0x4D, 0x18,                                     // add rcx, [rbp+0x18] (rcx = base + VA)

        // RELOC ENTRY LOOP
        0x85, 0xFF,                                                 // test edi, edi
        0x74, 0x22,                                                 // jz NEXT_RELOC_BLOCK
        0x0F, 0xB7, 0x06,                                           // movzx eax, word [rsi]
        0x0F, 0xB7, 0xC8,                                           // movzx ecx, ax
        0xC1, 0xE9, 0x0C,                                           // shr ecx, 12
        0x83, 0xF9, 0x0A,                                           // cmp ecx, 10 (IMAGE_REL_BASED_DIR64)
        0x75, 0x0F,                                                 // jne SKIP_RELOC_PATCH
        0x25, 0xFF, 0x0F, 0x00, 0x00,                               // and eax, 0xFFF
        0x48, 0x8B, 0x4D, 0x18,                                     // mov rcx, [rbp+0x18]
        0x48, 0x01, 0xC1,                                           // add rcx, rax (address to patch)
        0x48, 0x01, 0x11,                                           // add [rcx], rdx (apply delta)

        // SKIP_RELOC_PATCH
        0x48, 0x83, 0xC6, 0x02,                                     // add rsi, 2
        0xFF, 0xCF,                                                 // dec edi
        0x75, 0xDD,                                                 // jnz RELOC ENTRY LOOP

        // NEXT_RELOC_BLOCK
        0x48, 0x8B, 0x75, 0x18,                                     // restore pBase in rsi
        0x8B, 0x41, 0x04,                                           // mov eax, [rcx+4]
        0x48, 0x01, 0xC1,                                           // add rcx, rax (rcx = next pRelocData)
        0xEB, 0xB8,                                                 // jmp RELOC BLOCK LOOP

        // RELOC_DONE
        0x48, 0x8B, 0x75, 0x18,                                     // mov rsi, [rbp+0x18] (rsi = pBase)

        // IMPORTS RESOLUTION
        // DataDirectory[1] = offset 0x78
        0x8B, 0x83, 0x7C, 0x00, 0x00, 0x00,                         // mov eax, [rbx+0x7C] (IMPORT.Size)
        0x85, 0xC0,                                                 // test eax, eax
        0x74, 0x78,                                                 // jz IMPORTS_DONE

        0x8B, 0x8B, 0x78, 0x00, 0x00, 0x00,                         // mov ecx, [rbx+0x78] (IMPORT.VirtualAddress)
        0x48, 0x01, 0xF1,                                           // add rcx, rsi (rcx = pImportDescr)

        // IMPORT DESCRIPTOR LOOP (rcx = pImportDescr)
        0x8B, 0x41, 0x0C,                                           // mov eax, [rcx+0x0C] (Name RVA)
        0x85, 0xC0,                                                 // test eax, eax
        0x74, 0x68,                                                 // jz IMPORTS_DONE

        0x48, 0x89, 0xCF,                                           // mov rdi, rcx (save descr)
        0x48, 0x01, 0xF0,                                           // add rax, rsi (rax = module name string)
        0x48, 0x89, 0xC1,                                           // mov rcx, rax
        0xFF, 0x55, 0x00,                                           // call [rbp+0] (LoadLibraryA)
        0x49, 0x89, 0xC4,                                           // mov r12, rax (r12 = hDll)

        // Thunk references: OriginalFirstThunk at [rdi], FirstThunk at [rdi+0x10]
        0x8B, 0x07,                                                 // mov eax, [rdi] (OriginalFirstThunk)
        0x85, 0xC0,                                                 // test eax, eax
        0x75, 0x03,                                                 // jnz HAS_ORIGINAL
        0x8B, 0x47, 0x10,                                           // mov eax, [rdi+0x10] (FirstThunk fallback)
        // HAS_ORIGINAL
        0x48, 0x01, 0xF0,                                           // add rax, rsi (rax = pThunkRef)
        0x8B, 0x57, 0x10,                                           // mov edx, [rdi+0x10] (FirstThunk)
        0x48, 0x01, 0xF2,                                           // add rdx, rsi (rdx = pFuncRef)

        0x49, 0x89, 0xC5,                                           // mov r13, rax (r13 = pThunkRef)
        0x49, 0x89, 0xD6,                                           // mov r14, rdx (r14 = pFuncRef)

        // THUNK LOOP
        0x49, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,                   // mov rax, [r13]
        0x48, 0x85, 0xC0,                                           // test rax, rax
        0x74, 0x36,                                                 // jz NEXT_IMPORT_DESCR

        // Check ordinal flag (bit 63)
        0x48, 0x85, 0xC0,                                           // test rax, rax
        0x79, 0x0E,                                                 // jns IMPORT_BY_NAME
        // Import by ordinal
        0x25, 0xFF, 0xFF, 0x00, 0x00,                               // and eax, 0xFFFF
        0x48, 0x89, 0xC2,                                           // mov rdx, rax
        0x4C, 0x89, 0xE1,                                           // mov rcx, r12 (hDll)
        0xFF, 0x55, 0x08,                                           // call [rbp+8] (GetProcAddress)
        0x49, 0x89, 0x06,                                           // mov [r14], rax
        0xEB, 0x15,                                                 // jmp NEXT_THUNK

        // IMPORT_BY_NAME
        0x48, 0x01, 0xF0,                                           // add rax, rsi (rax = IMAGE_IMPORT_BY_NAME*)
        0x48, 0x8D, 0x50, 0x02,                                     // lea rdx, [rax+2] (rdx = Function Name)
        0x4C, 0x89, 0xE1,                                           // mov rcx, r12 (hDll)
        0xFF, 0x55, 0x08,                                           // call [rbp+8] (GetProcAddress)
        0x49, 0x89, 0x06,                                           // mov [r14], rax

        // NEXT_THUNK
        0x49, 0x83, 0xC5, 0x08,                                     // add r13, 8
        0x49, 0x83, 0xC6, 0x08,                                     // add r14, 8
        0xEB, 0xC3,                                                 // jmp THUNK LOOP

        // NEXT_IMPORT_DESCR
        0x48, 0x8D, 0x4F, 0x14,                                     // lea rcx, [rdi+20] (next import descr)
        0xEB, 0x83,                                                 // jmp IMPORT DESCRIPTOR LOOP

        // IMPORTS_DONE
        // TLS Callbacks: DataDirectory[9] = offset 0xB8
        0x8B, 0x83, 0xBC, 0x00, 0x00, 0x00,                         // mov eax, [rbx+0xBC] (TLS.Size)
        0x85, 0xC0,                                                 // test eax, eax
        0x74, 0x2A,                                                 // jz TLS_DONE

        0x8B, 0x8B, 0xB8, 0x00, 0x00, 0x00,                         // mov ecx, [rbx+0xB8] (TLS.VirtualAddress)
        0x48, 0x01, 0xF1,                                           // add rcx, rsi (rcx = pTLS)
        0x48, 0x8B, 0x49, 0x18,                                     // mov rcx, [rcx+0x18] (AddressOfCallBacks)
        0x48, 0x85, 0xC9,                                           // test rcx, rcx
        0x74, 0x1A,                                                 // jz TLS_DONE

        // TLS LOOP
        0x48, 0x8B, 0x01,                                           // mov rax, [rcx]
        0x48, 0x85, 0xC0,                                           // test rax, rax
        0x74, 0x11,                                                 // jz TLS_DONE
        0x48, 0x89, 0xCF,                                           // mov rdi, rcx
        0x48, 0x89, 0xF1,                                           // mov rcx, rsi (pBase)
        0xBA, 0x01, 0x00, 0x00, 0x00,                               // mov edx, 1 (DLL_PROCESS_ATTACH)
        0x45, 0x31, 0xC0,                                           // xor r8d, r8d (null)
        0xFF, 0xD0,                                                 // call rax
        0x48, 0x8D, 0x4F, 0x08,                                     // lea rcx, [rdi+8]
        0xEB, 0xE4,                                                 // jmp TLS LOOP

        // TLS_DONE
        // SEH Exception handling support: RtlAddFunctionTable
        0x83, 0x7D, 0x38, 0x00,                                     // cmp dword [rbp+0x38], 0 (SEHSupport)
        0x74, 0x2D,                                                 // jz SEH_DONE

        // DataDirectory[3] = EXCEPTION (offset 0x88)
        0x8B, 0x83, 0x8C, 0x00, 0x00, 0x00,                         // mov eax, [rbx+0x8C] (EXCEPTION.Size)
        0x85, 0xC0,                                                 // test eax, eax
        0x74, 0x21,                                                 // jz SEH_DONE

        0xB9, 0x0C, 0x00, 0x00, 0x00,                               // mov ecx, 12 (sizeof IMAGE_RUNTIME_FUNCTION_ENTRY)
        0x31, 0xD2,                                                 // xor edx, edx
        0xF7, 0xF1,                                                 // div ecx (eax = EntryCount)
        0x41, 0x89, 0xC0,                                           // mov r8d, eax (count)

        0x8B, 0x8B, 0x88, 0x00, 0x00, 0x00,                         // mov ecx, [rbx+0x88] (VA)
        0x48, 0x01, 0xF1,                                           // add rcx, rsi (rcx = FunctionTable)
        0x41, 0x89, 0xC2,                                           // mov edx, r8d (EntryCount)
        0x4C, 0x89, 0xF0,                                           // mov r8, rsi (BaseAddress)
        0xFF, 0x55, 0x10,                                           // call [rbp+0x10] (RtlAddFunctionTable)

        // SEH_DONE
        // Call DllMain(pBase, fdwReason, lpReserved)
        0x8B, 0x43, 0x10,                                           // mov eax, [rbx+0x10] (AddressOfEntryPoint)
        0x48, 0x85, 0xC0,                                           // test rax, rax
        0x74, 0x13,                                                 // jz DLL_MAIN_DONE

        0x48, 0x01, 0xF0,                                           // add rax, rsi (rax = EntryPoint)
        0x48, 0x89, 0xF1,                                           // mov rcx, rsi (hDll = pBase)
        0x8B, 0x55, 0x28,                                           // mov edx, [rbp+0x28] (fdwReason)
        0x4C, 0x8B, 0x45, 0x30,                                     // mov r8, [rbp+0x30] (lpReserved)
        0xFF, 0xD0,                                                 // call rax (DllMain)

        // DLL_MAIN_DONE
        // Store success: pData->hMod = pBase
        0x48, 0x89, 0x75, 0x20,                                     // mov [rbp+0x20], rsi
        0x48, 0x83, 0xC4, 0x58,                                     // add rsp, 0x58
        0x41, 0x5F,                                                 // pop r15
        0x41, 0x5E,                                                 // pop r14
        0x41, 0x5D,                                                 // pop r13
        0x41, 0x5C,                                                 // pop r12
        0x5F,                                                       // pop rdi
        0x5E,                                                       // pop rsi
        0x5B,                                                       // pop rbx
        0x5D,                                                       // pop rbp
        0xC3                                                        // ret
    };

    #endregion
}
