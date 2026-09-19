// ManualMapV2.cs
// A complete, working x64 PE Manual Map injector ported from the standalone
// ManualMap project into the Astate library.
//
// Stages:
//   1. PE header parsing
//   2. Process open / launch
//   3+4. Remote image allocation + section mapping
//   5. Base relocation
//   6. Import table resolution (with remote export directory walking, Toolhelp/PEB fallback)
//   7. TLS callbacks
//   8+9. Loader shellcode (RtlAddFunctionTable + DllMain call)
//   10. Optional header wipe, cleanup
//
// Usage:
//   ManualMapV2Result result = ManualMapV2.Inject(pid, dllBytes);
//   ManualMapV2Result result = ManualMapV2.Inject(process, dllPath);

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Astate;

// ============================================================================
//  PE DATA STRUCTURES
// ============================================================================

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_DOS_HEADER
{
    [FieldOffset(0)]  public ushort e_magic;
    [FieldOffset(2)]  public ushort e_cblp;
    [FieldOffset(4)]  public ushort e_cp;
    [FieldOffset(6)]  public ushort e_crlc;
    [FieldOffset(8)]  public ushort e_cparhdr;
    [FieldOffset(10)] public ushort e_minalloc;
    [FieldOffset(12)] public ushort e_maxalloc;
    [FieldOffset(14)] public ushort e_ss;
    [FieldOffset(16)] public ushort e_sp;
    [FieldOffset(18)] public ushort e_csum;
    [FieldOffset(20)] public ushort e_ip;
    [FieldOffset(22)] public ushort e_cs;
    [FieldOffset(24)] public ushort e_lfarlc;
    [FieldOffset(26)] public ushort e_ovno;
    [FieldOffset(28)] public ulong  e_res;
    [FieldOffset(36)] public ushort e_oemid;
    [FieldOffset(38)] public ushort e_oeminfo;
    [FieldOffset(40)] public ulong  e_res2a;
    [FieldOffset(48)] public ulong  e_res2b;
    [FieldOffset(56)] public uint   e_res2c;
    [FieldOffset(60)] public int    e_lfanew;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_FILE_HEADER
{
    [FieldOffset(0)]  public ushort Machine;
    [FieldOffset(2)]  public ushort NumberOfSections;
    [FieldOffset(4)]  public uint   TimeDateStamp;
    [FieldOffset(8)]  public uint   PointerToSymbolTable;
    [FieldOffset(12)] public uint   NumberOfSymbols;
    [FieldOffset(16)] public ushort SizeOfOptionalHeader;
    [FieldOffset(18)] public ushort Characteristics;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_DATA_DIRECTORY
{
    [FieldOffset(0)] public uint VirtualAddress;
    [FieldOffset(4)] public uint Size;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_OPTIONAL_HEADER64
{
    [FieldOffset(0)]   public ushort Magic;
    [FieldOffset(2)]   public byte   MajorLinkerVersion;
    [FieldOffset(3)]   public byte   MinorLinkerVersion;
    [FieldOffset(4)]   public uint   SizeOfCode;
    [FieldOffset(8)]   public uint   SizeOfInitializedData;
    [FieldOffset(12)]  public uint   SizeOfUninitializedData;
    [FieldOffset(16)]  public uint   AddressOfEntryPoint;
    [FieldOffset(20)]  public uint   BaseOfCode;
    [FieldOffset(24)]  public ulong  ImageBase;
    [FieldOffset(32)]  public uint   SectionAlignment;
    [FieldOffset(36)]  public uint   FileAlignment;
    [FieldOffset(40)]  public ushort MajorOperatingSystemVersion;
    [FieldOffset(42)]  public ushort MinorOperatingSystemVersion;
    [FieldOffset(44)]  public ushort MajorImageVersion;
    [FieldOffset(46)]  public ushort MinorImageVersion;
    [FieldOffset(48)]  public ushort MajorSubsystemVersion;
    [FieldOffset(50)]  public ushort MinorSubsystemVersion;
    [FieldOffset(52)]  public uint   Win32VersionValue;
    [FieldOffset(56)]  public uint   SizeOfImage;
    [FieldOffset(60)]  public uint   SizeOfHeaders;
    [FieldOffset(64)]  public uint   CheckSum;
    [FieldOffset(68)]  public ushort Subsystem;
    [FieldOffset(70)]  public ushort DllCharacteristics;
    [FieldOffset(72)]  public ulong  SizeOfStackReserve;
    [FieldOffset(80)]  public ulong  SizeOfStackCommit;
    [FieldOffset(88)]  public ulong  SizeOfHeapReserve;
    [FieldOffset(96)]  public ulong  SizeOfHeapCommit;
    [FieldOffset(104)] public uint   LoaderFlags;
    [FieldOffset(108)] public uint   NumberOfRvaAndSizes;
    [FieldOffset(112)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory0;
    [FieldOffset(120)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory1;
    [FieldOffset(128)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory2;
    [FieldOffset(136)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory3;
    [FieldOffset(144)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory4;
    [FieldOffset(152)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory5;
    [FieldOffset(160)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory6;
    [FieldOffset(168)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory7;
    [FieldOffset(176)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory8;
    [FieldOffset(184)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory9;
    [FieldOffset(192)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory10;
    [FieldOffset(200)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory11;
    [FieldOffset(208)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory12;
    [FieldOffset(216)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory13;
    [FieldOffset(224)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory14;
    [FieldOffset(232)] public Mmv2_IMAGE_DATA_DIRECTORY DataDirectory15;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_NT_HEADERS64
{
    [FieldOffset(0)]  public uint                         Signature;
    [FieldOffset(4)]  public Mmv2_IMAGE_FILE_HEADER       FileHeader;
    [FieldOffset(24)] public Mmv2_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
}

[StructLayout(LayoutKind.Explicit)]
internal unsafe struct Mmv2_IMAGE_SECTION_HEADER
{
    [FieldOffset(0)]  public fixed byte Name[8];
    [FieldOffset(8)]  public uint       VirtualSize;
    [FieldOffset(12)] public uint       VirtualAddress;
    [FieldOffset(16)] public uint       SizeOfRawData;
    [FieldOffset(20)] public uint       PointerToRawData;
    [FieldOffset(24)] public uint       PointerToRelocations;
    [FieldOffset(28)] public uint       PointerToLinenumbers;
    [FieldOffset(32)] public ushort     NumberOfRelocations;
    [FieldOffset(34)] public ushort     NumberOfLinenumbers;
    [FieldOffset(36)] public uint       Characteristics;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_BASE_RELOCATION
{
    [FieldOffset(0)] public uint VirtualAddress;
    [FieldOffset(4)] public uint SizeOfBlock;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_IMPORT_DESCRIPTOR
{
    [FieldOffset(0)]  public uint OriginalFirstThunk;
    [FieldOffset(4)]  public uint TimeDateStamp;
    [FieldOffset(8)]  public uint ForwarderChain;
    [FieldOffset(12)] public uint Name;
    [FieldOffset(16)] public uint FirstThunk;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_THUNK_DATA64
{
    [FieldOffset(0)] public ulong AddressOfData;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_TLS_DIRECTORY64
{
    [FieldOffset(0)]  public ulong StartAddressOfRawData;
    [FieldOffset(8)]  public ulong EndAddressOfRawData;
    [FieldOffset(16)] public ulong AddressOfIndex;
    [FieldOffset(24)] public ulong AddressOfCallBacks;
    [FieldOffset(32)] public uint  SizeOfZeroFill;
    [FieldOffset(36)] public uint  Characteristics;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_RUNTIME_FUNCTION_ENTRY
{
    [FieldOffset(0)] public uint BeginAddress;
    [FieldOffset(4)] public uint EndAddress;
    [FieldOffset(8)] public uint UnwindInfoAddress;
}

[StructLayout(LayoutKind.Explicit)]
internal struct Mmv2_IMAGE_EXPORT_DIRECTORY
{
    [FieldOffset(0)]  public uint   Characteristics;
    [FieldOffset(4)]  public uint   TimeDateStamp;
    [FieldOffset(8)]  public ushort MajorVersion;
    [FieldOffset(10)] public ushort MinorVersion;
    [FieldOffset(12)] public uint   Name;
    [FieldOffset(16)] public uint   Base;
    [FieldOffset(20)] public uint   NumberOfFunctions;
    [FieldOffset(24)] public uint   NumberOfNames;
    [FieldOffset(28)] public uint   AddressOfFunctions;
    [FieldOffset(32)] public uint   AddressOfNames;
    [FieldOffset(36)] public uint   AddressOfNameOrdinals;
}

// ============================================================================
//  LOADER PARAMETER STRUCT (passed to shellcode in target process)
// ============================================================================

[StructLayout(LayoutKind.Sequential)]
internal struct Mmv2_LoaderParams
{
    public ulong pDllBase;             // +0x00  Remote base of mapped DLL
    public ulong pLoadLibraryA;        // +0x08  VA of kernel32!LoadLibraryA in target
    public ulong pGetProcAddress;      // +0x10  VA of kernel32!GetProcAddress in target
    public ulong pRtlAddFunctionTable; // +0x18  VA of ntdll!RtlAddFunctionTable in target
    public ulong pExceptionDir;        // +0x20  VA of IMAGE_RUNTIME_FUNCTION_ENTRY[] in target
    public uint  FunctionTableCount;   // +0x28  Number of RUNTIME_FUNCTION entries
    public uint  AddressOfEntryPoint;  // +0x2C  RVA of DllMain
    public uint  Completed;            // +0x30  Shellcode sets this to 1 on completion
    public uint  EntryPointResult;     // +0x34  Return value of DllMain (BOOL)
}

// ============================================================================
//  TOOLHELP STRUCTURES
// ============================================================================

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct Mmv2_MODULEENTRY32W
{
    public uint   dwSize;
    public uint   th32ModuleID;
    public uint   th32ProcessID;
    public uint   GlblcntUsage;
    public uint   ProccntUsage;
    public IntPtr modBaseAddr;
    public uint   modBaseSize;
    public IntPtr hModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string szModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string szExePath;
}

// ============================================================================
//  PARSED PE IMAGE
// ============================================================================

internal sealed class Mmv2_PeImage
{
    public byte[]                      RawBytes        { get; init; } = null!;
    public Mmv2_IMAGE_DOS_HEADER       DosHeader       { get; init; }
    public Mmv2_IMAGE_NT_HEADERS64     NtHeaders       { get; init; }
    public Mmv2_IMAGE_SECTION_HEADER[] Sections        { get; init; } = null!;
    public Mmv2_IMAGE_DATA_DIRECTORY[] DataDirectories { get; init; } = null!;

    public uint  SizeOfImage         => NtHeaders.OptionalHeader.SizeOfImage;
    public uint  SizeOfHeaders       => NtHeaders.OptionalHeader.SizeOfHeaders;
    public uint  AddressOfEntryPoint => NtHeaders.OptionalHeader.AddressOfEntryPoint;
    public ulong PreferredImageBase  => NtHeaders.OptionalHeader.ImageBase;

    public Mmv2_IMAGE_DATA_DIRECTORY ExportDir    => DataDirectories[0];
    public Mmv2_IMAGE_DATA_DIRECTORY ImportDir    => DataDirectories[1];
    public Mmv2_IMAGE_DATA_DIRECTORY ExceptionDir => DataDirectories[3];
    public Mmv2_IMAGE_DATA_DIRECTORY RelocDir     => DataDirectories[5];
    public Mmv2_IMAGE_DATA_DIRECTORY TlsDir       => DataDirectories[9];
}

// ============================================================================
//  RESULT TYPE
// ============================================================================

/// <summary>
/// Result of a ManualMapV2 injection attempt.
/// </summary>
public sealed class ManualMapV2Result
{
    public bool   Success   { get; init; }
    public nint   ImageBase { get; init; }
    public string Message   { get; init; } = string.Empty;
    public int    ErrorCode { get; init; }
}

// ============================================================================
//  MAIN ENTRY POINT
// ============================================================================

/// <summary>
/// Working x64 PE Manual Map injector. Parses the PE, allocates a remote image,
/// applies relocations, resolves imports, runs TLS callbacks, then executes the
/// loader shellcode which calls RtlAddFunctionTable and DllMain.
/// </summary>
public static class ManualMapV2
{
    // ------------------------------------------------------------------
    //  Public inject overloads
    // ------------------------------------------------------------------

    /// <summary>Injects a DLL by file path into the given process.</summary>
    public static ManualMapV2Result Inject(Process targetProcess, string dllPath,
        bool wipeHeaders = false)
    {
        if (targetProcess is null || targetProcess.HasExited)
            return Fail("Target process is not running.");
        if (!File.Exists(dllPath))
            return Fail($"DLL file not found: {dllPath}");
        byte[] bytes = File.ReadAllBytes(dllPath);
        return Inject(targetProcess.Id, bytes, wipeHeaders);
    }

    /// <summary>Injects a DLL from a byte array into the given PID.</summary>
    public static ManualMapV2Result Inject(int targetPid, byte[] dllBytes,
        bool wipeHeaders = false)
    {
        if (targetPid <= 0)
            return Fail("Invalid process ID.");
        if (dllBytes is null || dllBytes.Length < 0x1000)
            return Fail("DLL byte buffer is too small or null.");

        // Stage 1 - Parse PE
        Mmv2_PeImage pe;
        try { pe = ParsePe(dllBytes); }
        catch (Exception ex) { return Fail($"PE parsing failed: {ex.Message}"); }

        // Stage 2 - Open process
        IntPtr hProcess = Mmv2Native.OpenProcess(0x1F0FFF, false, (uint)targetPid);
        if (hProcess == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return Fail($"OpenProcess failed (PID {targetPid}). Error 0x{err:X8}", err);
        }

        IntPtr remoteBase = IntPtr.Zero;
        try
        {
            // Stage 3+4 - Allocate and map sections
            try { remoteBase = MapImageIntoTarget(hProcess, pe); }
            catch (Exception ex) { return Fail($"Section mapping failed: {ex.Message}"); }

            // Stage 5 - Base relocations
            try { ApplyRelocations(hProcess, pe, remoteBase); }
            catch (Exception ex) { return Fail($"Relocation failed: {ex.Message}"); }

            // Stage 6 - Resolve imports
            try { ResolveImports(hProcess, pe, remoteBase); }
            catch (Exception ex) { return Fail($"Import resolution failed: {ex.Message}"); }

            // Stage 7 - TLS callbacks
            try { InvokeTlsCallbacks(hProcess, pe, remoteBase); }
            catch (Exception ex) { return Fail($"TLS callbacks failed: {ex.Message}"); }

            // Stage 8+9 - Shellcode (RtlAddFunctionTable + DllMain)
            bool dllMainOk;
            try { dllMainOk = ExecuteShellcode(hProcess, pe, remoteBase); }
            catch (Exception ex) { return Fail($"Shellcode execution failed: {ex.Message}"); }

            // Stage 10 - Optional header wipe
            if (wipeHeaders)
            {
                try { WipeHeaders(hProcess, remoteBase, pe.SizeOfHeaders); }
                catch { /* non-fatal */ }
            }

            nint baseNint = (nint)(long)remoteBase;
            if (dllMainOk)
                return new ManualMapV2Result { Success = true, ImageBase = baseNint,
                    Message = $"Manual map succeeded. DllMain returned TRUE. Base: 0x{(long)remoteBase:X}" };
            else
                return new ManualMapV2Result { Success = false, ImageBase = baseNint,
                    Message = "Manual map complete but DllMain returned FALSE." };
        }
        catch (Exception ex)
        {
            return Fail($"Unexpected error during injection: {ex.Message}");
        }
        finally
        {
            Mmv2Native.CloseHandle(hProcess);
        }
    }

    // ------------------------------------------------------------------
    //  Stage 1 - PE parsing
    // ------------------------------------------------------------------

    private const ushort IMAGE_DOS_SIGNATURE           = 0x5A4D;
    private const uint   IMAGE_NT_SIGNATURE            = 0x00004550;
    private const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B;
    private const ushort IMAGE_FILE_MACHINE_AMD64      = 0x8664;

    private static unsafe Mmv2_PeImage ParsePe(byte[] raw)
    {
        fixed (byte* pBase = raw)
        {
            if (raw.Length < Marshal.SizeOf<Mmv2_IMAGE_DOS_HEADER>())
                throw new BadImageFormatException("File too small for DOS header.");

            Mmv2_IMAGE_DOS_HEADER dos = *(Mmv2_IMAGE_DOS_HEADER*)pBase;
            if (dos.e_magic != IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException($"Invalid DOS signature 0x{dos.e_magic:X4}.");

            int ntOff = dos.e_lfanew;
            if (ntOff <= 0 || ntOff + Marshal.SizeOf<Mmv2_IMAGE_NT_HEADERS64>() > raw.Length)
                throw new BadImageFormatException("e_lfanew is out of file bounds.");

            Mmv2_IMAGE_NT_HEADERS64 nt = *(Mmv2_IMAGE_NT_HEADERS64*)(pBase + ntOff);
            if (nt.Signature != IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException($"Invalid NT signature 0x{nt.Signature:X8}.");
            if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                throw new BadImageFormatException("Only 64-bit (PE32+) DLLs are supported.");
            if (nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
                throw new BadImageFormatException($"Machine type 0x{nt.FileHeader.Machine:X4} is not AMD64.");

            // Data directories
            var dirs  = new Mmv2_IMAGE_DATA_DIRECTORY[16];
            Mmv2_IMAGE_DATA_DIRECTORY* pDir = &nt.OptionalHeader.DataDirectory0;
            int count = (int)Math.Min(nt.OptionalHeader.NumberOfRvaAndSizes, 16u);
            for (int i = 0; i < count; i++) dirs[i] = pDir[i];

            // Section headers
            int sectionTableOffset = ntOff + 4
                + Marshal.SizeOf<Mmv2_IMAGE_FILE_HEADER>()
                + nt.FileHeader.SizeOfOptionalHeader;
            int numSections = nt.FileHeader.NumberOfSections;
            int sectionSize = Marshal.SizeOf<Mmv2_IMAGE_SECTION_HEADER>();

            if (sectionTableOffset + numSections * sectionSize > raw.Length)
                throw new BadImageFormatException("Section table extends beyond file bounds.");

            var sections = new Mmv2_IMAGE_SECTION_HEADER[numSections];
            for (int i = 0; i < numSections; i++)
                sections[i] = *(Mmv2_IMAGE_SECTION_HEADER*)(pBase + sectionTableOffset + i * sectionSize);

            return new Mmv2_PeImage
            {
                RawBytes        = raw,
                DosHeader       = dos,
                NtHeaders       = nt,
                Sections        = sections,
                DataDirectories = dirs,
            };
        }
    }

    /// <summary>Converts an RVA to a file offset by walking the section table.</summary>
    private static int RvaToFileOffset(Mmv2_PeImage pe, uint rva)
    {
        if (rva < pe.SizeOfHeaders) return (int)rva;
        foreach (var sec in pe.Sections)
        {
            uint secEnd = sec.VirtualAddress + Math.Max(sec.VirtualSize, sec.SizeOfRawData);
            if (rva >= sec.VirtualAddress && rva < secEnd)
            {
                uint off = rva - sec.VirtualAddress + sec.PointerToRawData;
                if (off >= pe.RawBytes.Length)
                    throw new BadImageFormatException($"RVA 0x{rva:X} maps beyond EOF.");
                return (int)off;
            }
        }
        throw new BadImageFormatException($"RVA 0x{rva:X} not in any section.");
    }

    private static string ReadAsciiString(byte[] buf, int offset)
    {
        int end = offset;
        while (end < buf.Length && buf[end] != 0) end++;
        return Encoding.ASCII.GetString(buf, offset, end - offset);
    }

    // ------------------------------------------------------------------
    //  Stage 3+4 - Remote image allocation and section mapping
    // ------------------------------------------------------------------

    private static IntPtr MapImageIntoTarget(IntPtr hProcess, Mmv2_PeImage pe)
    {
        IntPtr remoteBase = AllocRemote(hProcess, pe.SizeOfImage);
        try
        {
            WriteRemote(hProcess, remoteBase, pe.RawBytes, 0, (int)pe.SizeOfHeaders);
            foreach (var sec in pe.Sections)
            {
                if (sec.SizeOfRawData == 0) continue;
                uint copyLen = Math.Min(sec.VirtualSize, sec.SizeOfRawData);
                IntPtr dest  = remoteBase + (int)sec.VirtualAddress;
                WriteRemote(hProcess, dest, pe.RawBytes, (int)sec.PointerToRawData, (int)copyLen);
            }
            return remoteBase;
        }
        catch { FreeRemote(hProcess, remoteBase); throw; }
    }

    // ------------------------------------------------------------------
    //  Stage 5 - Base relocations
    // ------------------------------------------------------------------

    private const ushort IMAGE_REL_BASED_DIR64 = 10;

    private static void ApplyRelocations(IntPtr hProcess, Mmv2_PeImage pe, IntPtr remoteBase)
    {
        var relocDir = pe.RelocDir;
        if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) return;

        long delta = (long)remoteBase - (long)pe.PreferredImageBase;
        if (delta == 0) return;

        int    relocSize = (int)relocDir.Size;
        IntPtr relocAddr = remoteBase + (int)relocDir.VirtualAddress;
        byte[] relocData = ReadRemote(hProcess, relocAddr, relocSize);

        int blockOff  = 0;
        int relocHdrSz = Marshal.SizeOf<Mmv2_IMAGE_BASE_RELOCATION>();

        while (blockOff + relocHdrSz <= relocSize)
        {
            Mmv2_IMAGE_BASE_RELOCATION block;
            unsafe { fixed (byte* p = relocData) block = *(Mmv2_IMAGE_BASE_RELOCATION*)(p + blockOff); }

            if (block.VirtualAddress == 0 && block.SizeOfBlock == 0) break;
            if (block.SizeOfBlock < (uint)relocHdrSz) break;

            int entryCount  = ((int)block.SizeOfBlock - relocHdrSz) / 2;
            int entryOffset = blockOff + relocHdrSz;

            for (int i = 0; i < entryCount; i++)
            {
                ushort entry;
                unsafe { fixed (byte* p = relocData) entry = *(ushort*)(p + entryOffset + i * 2); }

                ushort type   = (ushort)(entry >> 12);
                ushort offset = (ushort)(entry & 0x0FFF);

                if (type == IMAGE_REL_BASED_DIR64)
                {
                    IntPtr patchAddr = remoteBase + (int)block.VirtualAddress + offset;
                    ulong cur = 0;
                    unsafe { ReadProcessMemory(hProcess, patchAddr, &cur, 8); }
                    ulong patched = (ulong)((long)cur + delta);
                    unsafe { WriteProcessMemory(hProcess, patchAddr, &patched, 8); }
                }
            }
            blockOff += (int)block.SizeOfBlock;
        }
    }

    // ------------------------------------------------------------------
    //  Stage 6 - Import table resolution
    // ------------------------------------------------------------------

    private const ulong IMAGE_ORDINAL_FLAG64 = 0x8000000000000000UL;

    private static readonly Dictionary<string, IntPtr> s_remoteModCache =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, IntPtr> s_localModCache =
        new(StringComparer.OrdinalIgnoreCase);

    private static void ResolveImports(IntPtr hProcess, Mmv2_PeImage pe, IntPtr remoteBase)
    {
        var importDir = pe.ImportDir;
        if (importDir.VirtualAddress == 0 || importDir.Size == 0) return;

        s_remoteModCache.Clear();
        s_localModCache.Clear();

        int descSize    = Marshal.SizeOf<Mmv2_IMAGE_IMPORT_DESCRIPTOR>();
        int descFileOff = RvaToFileOffset(pe, importDir.VirtualAddress);
        int thunkSize   = Marshal.SizeOf<Mmv2_IMAGE_THUNK_DATA64>();

        while (true)
        {
            Mmv2_IMAGE_IMPORT_DESCRIPTOR desc;
            unsafe { fixed (byte* p = pe.RawBytes) desc = *(Mmv2_IMAGE_IMPORT_DESCRIPTOR*)(p + descFileOff); }
            if (desc.Name == 0) break;

            string modName = ReadAsciiString(pe.RawBytes, RvaToFileOffset(pe, desc.Name));

            IntPtr remoteModBase = IntPtr.Zero;
            bool useFallback = false;
            try { remoteModBase = EnsureModuleLoadedInTarget(hProcess, modName); }
            catch { useFallback = true; }

            uint intRva      = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
            uint iatRva      = desc.FirstThunk;
            int  intFileBase = RvaToFileOffset(pe, intRva);
            int  thunkIdx    = 0;

            while (true)
            {
                Mmv2_IMAGE_THUNK_DATA64 thunk;
                unsafe { fixed (byte* p = pe.RawBytes) thunk = *(Mmv2_IMAGE_THUNK_DATA64*)(p + intFileBase + thunkIdx * thunkSize); }
                if (thunk.AddressOfData == 0) break;

                ulong resolved;
                if ((thunk.AddressOfData & IMAGE_ORDINAL_FLAG64) != 0)
                {
                    ushort ord = (ushort)(thunk.AddressOfData & 0xFFFF);
                    if (!useFallback && remoteModBase != IntPtr.Zero &&
                        TryGetRemoteExportByOrdinal(hProcess, remoteModBase, modName, ord, out resolved))
                    { /* resolved set */ }
                    else
                        resolved = GetLocalExportByOrdinal(modName, ord);
                }
                else
                {
                    uint   ibnRva   = (uint)(thunk.AddressOfData & 0x7FFFFFFFFFFFFFFF);
                    int    ibnFile  = RvaToFileOffset(pe, ibnRva);
                    string funcName = ReadAsciiString(pe.RawBytes, ibnFile + 2); // +2 skips Hint
                    if (!useFallback && remoteModBase != IntPtr.Zero &&
                        TryGetRemoteExportByName(hProcess, remoteModBase, modName, funcName, out resolved))
                    { /* resolved set */ }
                    else
                        resolved = GetLocalExportByName(modName, funcName);
                }

                IntPtr iatSlot = remoteBase + (int)iatRva + thunkIdx * thunkSize;
                unsafe { WriteProcessMemory(hProcess, iatSlot, &resolved, 8); }
                thunkIdx++;
            }

            descFileOff += descSize;
        }
    }

    // --- Remote module helpers ---

    private static IntPtr EnsureModuleLoadedInTarget(IntPtr hProcess, string moduleName)
    {
        if (s_remoteModCache.TryGetValue(moduleName, out IntPtr cached)) return cached;

        // Resolve API set name via local LoadLibrary
        string resolved = moduleName;
        try
        {
            IntPtr hLocal = Mmv2Native.LoadLibraryA(moduleName);
            if (hLocal != IntPtr.Zero)
            {
                var sb = new StringBuilder(1024);
                if (Mmv2Native.GetModuleFileNameW(hLocal, sb, 1024) > 0)
                {
                    string fn = Path.GetFileName(sb.ToString());
                    if (!string.IsNullOrEmpty(fn)) resolved = fn;
                }
            }
        }
        catch { }

        IntPtr existing = FindModuleBaseInTarget(hProcess, resolved);
        if (existing == IntPtr.Zero && !resolved.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
            existing = FindModuleBaseInTarget(hProcess, moduleName);

        if (existing != IntPtr.Zero)
        {
            s_remoteModCache[moduleName] = existing;
            s_remoteModCache[resolved]   = existing;
            return existing;
        }

        // Load it via remote thread
        LoadLibraryInTarget(hProcess, moduleName);

        IntPtr modBase = FindModuleBaseInTarget(hProcess, resolved);
        if (modBase == IntPtr.Zero && !resolved.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
            modBase = FindModuleBaseInTarget(hProcess, moduleName);
        if (modBase == IntPtr.Zero)
            throw new InvalidOperationException($"LoadLibraryA succeeded but '{moduleName}' not in module list.");

        s_remoteModCache[moduleName] = modBase;
        s_remoteModCache[resolved]   = modBase;
        return modBase;
    }

    private static IntPtr FindModuleBaseInTarget(IntPtr hProcess, string moduleName)
    {
        // Try EnumProcessModulesEx first
        try
        {
            int bufSize = 4096;
            while (true)
            {
                var modules = new IntPtr[bufSize / IntPtr.Size];
                if (!Mmv2Native.EnumProcessModulesEx(hProcess, modules, (uint)bufSize, out uint needed, 0x03))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == 0x7A && bufSize < (int)needed) { bufSize = (int)needed + 256; continue; }
                    break;
                }
                int count = (int)(needed / (uint)IntPtr.Size);
                for (int i = 0; i < count; i++)
                {
                    var sb2 = new StringBuilder(1024);
                    if (Mmv2Native.GetModuleFileNameEx(hProcess, modules[i], sb2, 1024) > 0)
                        if (Path.GetFileName(sb2.ToString()).Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                            return modules[i];
                }
                break;
            }
        }
        catch { }

        // Toolhelp fallback
        try { return FindModuleViaToolhelp(hProcess, moduleName); }
        catch { }

        return IntPtr.Zero;
    }

    private static IntPtr FindModuleViaToolhelp(IntPtr hProcess, string moduleName)
    {
        uint pid = Mmv2Native.GetProcessId(hProcess);
        IntPtr hSnap = Mmv2Native.CreateToolhelp32Snapshot(0x8 | 0x10, pid);
        if (hSnap == new IntPtr(-1) || hSnap == IntPtr.Zero)
        {
            Thread.Sleep(200);
            hSnap = Mmv2Native.CreateToolhelp32Snapshot(0x8 | 0x10, pid);
            if (hSnap == new IntPtr(-1) || hSnap == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        try
        {
            var me = new Mmv2_MODULEENTRY32W { dwSize = (uint)Marshal.SizeOf<Mmv2_MODULEENTRY32W>() };
            if (!Mmv2Native.Module32FirstW(hSnap, ref me)) return IntPtr.Zero;
            do
            {
                bool nm = me.szModule?.Equals(moduleName, StringComparison.OrdinalIgnoreCase) ?? false;
                bool pm = !nm && me.szExePath != null &&
                          Path.GetFileName(me.szExePath).Equals(moduleName, StringComparison.OrdinalIgnoreCase);
                if (nm || pm) return me.modBaseAddr;
            }
            while (Mmv2Native.Module32NextW(hSnap, ref me));
            return IntPtr.Zero;
        }
        finally { Mmv2Native.CloseHandle(hSnap); }
    }

    private static void LoadLibraryInTarget(IntPtr hProcess, string moduleName)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(moduleName + '\0');
        IntPtr remoteStr = AllocRemote(hProcess, (nuint)nameBytes.Length, 0x04 /*PAGE_READWRITE*/);
        try
        {
            WriteRemote(hProcess, remoteStr, nameBytes, 0, nameBytes.Length);
            IntPtr hKernel32    = Mmv2Native.GetModuleHandleA("kernel32.dll");
            IntPtr pLoadLibrary = Mmv2Native.GetProcAddress(hKernel32, "LoadLibraryA");
            if (pLoadLibrary == IntPtr.Zero)
                throw new InvalidOperationException("Could not resolve LoadLibraryA.");
            IntPtr hThread = Mmv2Native.CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero,
                pLoadLibrary, remoteStr, 0, out _);
            if (hThread == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"CreateRemoteThread(LoadLibraryA) failed for '{moduleName}'.");
            try
            {
                uint w = Mmv2Native.WaitForSingleObject(hThread, 10_000);
                if (w != 0) throw new TimeoutException($"Timeout waiting for LoadLibraryA ('{moduleName}').");
            }
            finally { Mmv2Native.CloseHandle(hThread); }
        }
        finally { FreeRemote(hProcess, remoteStr); }
    }

    // --- Remote export resolution helpers ---

    private static bool TryGetRemoteExportByName(IntPtr hProcess, IntPtr modBase,
        string modName, string funcName, out ulong addr)
    {
        try { addr = GetRemoteExportByName(hProcess, modBase, modName, funcName); return true; }
        catch { addr = 0; return false; }
    }

    private static bool TryGetRemoteExportByOrdinal(IntPtr hProcess, IntPtr modBase,
        string modName, ushort ordinal, out ulong addr)
    {
        try { addr = GetRemoteExportByOrdinal(hProcess, modBase, ordinal); return true; }
        catch { addr = 0; return false; }
    }

    private static ulong GetRemoteExportByName(IntPtr hProcess, IntPtr modBase,
        string modName, string funcName, int depth = 0)
    {
        if (depth > 8) throw new InvalidOperationException("Forwarded export depth limit exceeded.");
        var expDir = ReadRemoteExportDir(hProcess, modBase, modName, out var expDataDir);

        byte[] nameRvas = ReadRemote(hProcess, modBase + (int)expDir.AddressOfNames,
            (int)(expDir.NumberOfNames * 4));
        byte[] ordinals = ReadRemote(hProcess, modBase + (int)expDir.AddressOfNameOrdinals,
            (int)(expDir.NumberOfNames * 2));
        byte[] funcRvas = ReadRemote(hProcess, modBase + (int)expDir.AddressOfFunctions,
            (int)(expDir.NumberOfFunctions * 4));

        for (uint i = 0; i < expDir.NumberOfNames; i++)
        {
            uint nameRva;
            unsafe { fixed (byte* p = nameRvas) nameRva = ((uint*)p)[i]; }
            byte[] nb = ReadRemote(hProcess, modBase + (int)nameRva, 256);
            if (!NullTermAscii(nb).Equals(funcName, StringComparison.Ordinal)) continue;

            ushort ordIdx;
            unsafe { fixed (byte* p = ordinals) ordIdx = ((ushort*)p)[i]; }
            uint funcRva;
            unsafe { fixed (byte* p = funcRvas) funcRva = ((uint*)p)[ordIdx]; }

            uint edEnd = expDataDir.VirtualAddress + expDataDir.Size;
            if (funcRva >= expDataDir.VirtualAddress && funcRva < edEnd)
                return ResolveForwardedExport(hProcess, modBase, funcRva, depth);
            return (ulong)((long)modBase + funcRva);
        }
        throw new EntryPointNotFoundException($"Export '{funcName}' not found in '{modName}'.");
    }

    private static ulong GetRemoteExportByOrdinal(IntPtr hProcess, IntPtr modBase,
        ushort ordinal, int depth = 0)
    {
        if (depth > 8) throw new InvalidOperationException("Forwarded export depth limit exceeded.");
        var expDir = ReadRemoteExportDir(hProcess, modBase, "(unknown)", out var expDataDir);

        int idx = ordinal - (int)expDir.Base;
        if (idx < 0 || (uint)idx >= expDir.NumberOfFunctions)
            throw new ArgumentOutOfRangeException(nameof(ordinal), $"Ordinal #{ordinal} out of range.");

        byte[] funcRvas = ReadRemote(hProcess, modBase + (int)expDir.AddressOfFunctions,
            (int)(expDir.NumberOfFunctions * 4));
        uint funcRva;
        unsafe { fixed (byte* p = funcRvas) funcRva = ((uint*)p)[idx]; }

        uint edEnd = expDataDir.VirtualAddress + expDataDir.Size;
        if (funcRva >= expDataDir.VirtualAddress && funcRva < edEnd)
            return ResolveForwardedExport(hProcess, modBase, funcRva, depth);
        return (ulong)((long)modBase + funcRva);
    }

    private static ulong ResolveForwardedExport(IntPtr hProcess, IntPtr modBase, uint funcRva, int depth)
    {
        byte[] fwdBytes = ReadRemote(hProcess, modBase + (int)funcRva, 256);
        string fwd = NullTermAscii(fwdBytes);
        int dot = fwd.IndexOf('.');
        if (dot < 0) throw new BadImageFormatException($"Bad forward string '{fwd}'.");
        string fwdMod = fwd[..dot];
        if (!fwdMod.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) fwdMod += ".dll";
        string fwdTarget = fwd[(dot + 1)..];
        IntPtr fwdBase = EnsureModuleLoadedInTarget(hProcess, fwdMod);
        if (fwdTarget.StartsWith('#') && ushort.TryParse(fwdTarget.AsSpan(1), out ushort fwdOrd))
            return GetRemoteExportByOrdinal(hProcess, fwdBase, fwdOrd, depth + 1);
        return GetRemoteExportByName(hProcess, fwdBase, fwdMod, fwdTarget, depth + 1);
    }

    private static Mmv2_IMAGE_EXPORT_DIRECTORY ReadRemoteExportDir(IntPtr hProcess, IntPtr modBase,
        string modName, out Mmv2_IMAGE_DATA_DIRECTORY expDataDir)
    {
        var dos = ReadRemoteStruct<Mmv2_IMAGE_DOS_HEADER>(hProcess, modBase);
        if (dos.e_magic != 0x5A4D)
            throw new BadImageFormatException($"Bad DOS sig in remote module '{modName}'.");
        var nt = ReadRemoteStruct<Mmv2_IMAGE_NT_HEADERS64>(hProcess, modBase + dos.e_lfanew);
        expDataDir = nt.OptionalHeader.DataDirectory0;
        if (expDataDir.VirtualAddress == 0)
            throw new InvalidOperationException($"'{modName}' has no export directory.");
        return ReadRemoteStruct<Mmv2_IMAGE_EXPORT_DIRECTORY>(hProcess, modBase + (int)expDataDir.VirtualAddress);
    }

    // --- Local resolution fallback ---

    private static IntPtr EnsureModuleLoadedLocally(string moduleName)
    {
        if (s_localModCache.TryGetValue(moduleName, out IntPtr cached)) return cached;
        IntPtr h = Mmv2Native.LoadLibraryA(moduleName);
        if (h == IntPtr.Zero)
            throw new InvalidOperationException(
                $"Local LoadLibraryA failed for '{moduleName}' (error {Marshal.GetLastWin32Error()}).");
        s_localModCache[moduleName] = h;
        return h;
    }

    private static ulong GetLocalExportByName(string moduleName, string funcName)
    {
        IntPtr h = EnsureModuleLoadedLocally(moduleName);
        IntPtr p = Mmv2Native.GetProcAddress(h, funcName);
        if (p == IntPtr.Zero)
            throw new EntryPointNotFoundException($"Export '{funcName}' not found locally in '{moduleName}'.");
        return (ulong)(long)p;
    }

    private static ulong GetLocalExportByOrdinal(string moduleName, ushort ordinal)
    {
        IntPtr h = EnsureModuleLoadedLocally(moduleName);
        IntPtr p = Mmv2Native.GetProcAddressByOrdinal(h, ordinal);
        if (p == IntPtr.Zero)
            throw new EntryPointNotFoundException($"Ordinal #{ordinal} not found locally in '{moduleName}'.");
        return (ulong)(long)p;
    }

    // ------------------------------------------------------------------
    //  Stage 7 - TLS callbacks
    // ------------------------------------------------------------------

    private static void InvokeTlsCallbacks(IntPtr hProcess, Mmv2_PeImage pe, IntPtr remoteBase)
    {
        var tlsDataDir = pe.TlsDir;
        if (tlsDataDir.VirtualAddress == 0 || tlsDataDir.Size == 0) return;

        IntPtr tlsDirAddr = remoteBase + (int)tlsDataDir.VirtualAddress;
        var tlsDir = ReadRemoteStruct<Mmv2_IMAGE_TLS_DIRECTORY64>(hProcess, tlsDirAddr);
        if (tlsDir.AddressOfCallBacks == 0) return;

        int idx = 0;
        while (true)
        {
            IntPtr cbEntry = (IntPtr)(long)(tlsDir.AddressOfCallBacks + (ulong)(idx * 8));
            byte[] cbBytes = ReadRemote(hProcess, cbEntry, 8);
            ulong  cbVa;
            unsafe { fixed (byte* p = cbBytes) cbVa = *(ulong*)p; }
            if (cbVa == 0) break;

            IntPtr hThread = Mmv2Native.CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero,
                (IntPtr)(long)cbVa, IntPtr.Zero, 0, out _);
            if (hThread == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"CreateRemoteThread failed for TLS callback [{idx}].");
            uint w = Mmv2Native.WaitForSingleObject(hThread, 10_000);
            Mmv2Native.CloseHandle(hThread);
            if (w != 0) throw new TimeoutException($"TLS callback [{idx}] timed out.");
            idx++;
        }
    }

    // ------------------------------------------------------------------
    //  Stage 8+9 - Loader shellcode (RtlAddFunctionTable + DllMain)
    // ------------------------------------------------------------------

    // Position-independent x64 shellcode. RCX = &LoaderParams on entry.
    //
    // Offsets:  +0x00 pDllBase  +0x08 pLoadLibA  +0x10 pGetProcAddr
    //           +0x18 pRtlAddFnTbl  +0x20 pExceptDir
    //           +0x28 FuncCount(u32) +0x2C AoEP(u32)
    //           +0x30 Completed(u32) +0x34 Result(u32)
    private static readonly byte[] s_shellcode =
    {
        0x53,                                              // push rbx
        0x56,                                              // push rsi
        0x57,                                              // push rdi
        0x48, 0x83, 0xEC, 0x20,                            // sub rsp, 0x20
        0x48, 0x8B, 0xD9,                                  // mov rbx, rcx  ; &params
        // RtlAddFunctionTable(pExceptionDir, Count, pDllBase)
        0x48, 0x8B, 0x4B, 0x20,                            // mov rcx, [rbx+0x20]
        0x8B, 0x53, 0x28,                                  // mov edx, [rbx+0x28]
        0x4C, 0x8B, 0x03,                                  // mov r8,  [rbx]
        0xFF, 0x53, 0x18,                                  // call [rbx+0x18]
        // DllMain(pDllBase, 1, 0)
        0x48, 0x8B, 0x0B,                                  // mov rcx, [rbx]
        0x48, 0x8B, 0xC1,                                  // mov rax, rcx
        0x8B, 0x53, 0x2C,                                  // mov edx, [rbx+0x2C]
        0x48, 0x03, 0xC2,                                  // add rax, rdx
        0xBA, 0x01, 0x00, 0x00, 0x00,                      // mov edx, 1
        0x4D, 0x33, 0xC0,                                  // xor r8d, r8d
        0xFF, 0xD0,                                        // call rax
        // Store result
        0x89, 0x43, 0x34,                                  // mov [rbx+0x34], eax
        0xC7, 0x43, 0x30, 0x01, 0x00, 0x00, 0x00,          // mov [rbx+0x30], 1
        // Epilogue
        0x48, 0x83, 0xC4, 0x20,                            // add rsp, 0x20
        0x5F,                                              // pop rdi
        0x5E,                                              // pop rsi
        0x5B,                                              // pop rbx
        0xC3,                                              // ret
    };

    private static bool ExecuteShellcode(IntPtr hProcess, Mmv2_PeImage pe, IntPtr remoteBase)
    {
        IntPtr hKernel32 = Mmv2Native.GetModuleHandleA("kernel32.dll");
        IntPtr hNtdll    = Mmv2Native.GetModuleHandleA("ntdll.dll");
        if (hKernel32 == IntPtr.Zero || hNtdll == IntPtr.Zero)
            throw new InvalidOperationException("Cannot get kernel32 / ntdll handles.");

        IntPtr pLoadLibraryA        = Mmv2Native.GetProcAddress(hKernel32, "LoadLibraryA");
        IntPtr pGetProcAddress      = Mmv2Native.GetProcAddress(hKernel32, "GetProcAddress");
        IntPtr pRtlAddFunctionTable = Mmv2Native.GetProcAddress(hNtdll,    "RtlAddFunctionTable");

        ulong pExceptionDir = 0;
        uint  functionCount = 0;
        var   excDir        = pe.ExceptionDir;
        if (excDir.VirtualAddress != 0 && excDir.Size != 0)
        {
            pExceptionDir = (ulong)((long)remoteBase + excDir.VirtualAddress);
            functionCount = excDir.Size / (uint)Marshal.SizeOf<Mmv2_IMAGE_RUNTIME_FUNCTION_ENTRY>();
        }

        var lp = new Mmv2_LoaderParams
        {
            pDllBase             = (ulong)(long)remoteBase,
            pLoadLibraryA        = (ulong)(long)pLoadLibraryA,
            pGetProcAddress      = (ulong)(long)pGetProcAddress,
            pRtlAddFunctionTable = pRtlAddFunctionTable != IntPtr.Zero
                                   ? (ulong)(long)pRtlAddFunctionTable : 0,
            pExceptionDir        = pExceptionDir,
            FunctionTableCount   = functionCount,
            AddressOfEntryPoint  = pe.AddressOfEntryPoint,
            Completed            = 0,
            EntryPointResult     = 0,
        };

        int totalSize      = s_shellcode.Length + Marshal.SizeOf<Mmv2_LoaderParams>();
        IntPtr remoteBlock = AllocRemote(hProcess, (nuint)totalSize, 0x40 /*PAGE_EXECUTE_READWRITE*/);
        try
        {
            IntPtr remoteShellcode = remoteBlock;
            IntPtr remoteParams    = remoteBlock + s_shellcode.Length;

            WriteRemote(hProcess, remoteShellcode, s_shellcode, 0, s_shellcode.Length);
            WriteRemoteStruct(hProcess, remoteParams, lp);

            IntPtr hThread = Mmv2Native.CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero,
                remoteShellcode, remoteParams, 0, out _);
            if (hThread == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "CreateRemoteThread failed for loader shellcode.");

            try
            {
                const int timeout  = 30_000;
                const int interval = 50;
                int elapsed = 0;
                bool done = false;
                while (elapsed < timeout)
                {
                    Thread.Sleep(interval);
                    elapsed += interval;
                    var cur = ReadRemoteStruct<Mmv2_LoaderParams>(hProcess, remoteParams);
                    if (cur.Completed != 0) { lp = cur; done = true; break; }
                }
                if (!done) throw new TimeoutException("Loader shellcode did not signal completion within 30 seconds.");
            }
            finally { Mmv2Native.CloseHandle(hThread); }

            return lp.EntryPointResult != 0;
        }
        finally { FreeRemote(hProcess, remoteBlock); }
    }

    // ------------------------------------------------------------------
    //  Stage 10 - Optional PE header wipe
    // ------------------------------------------------------------------

    private static void WipeHeaders(IntPtr hProcess, IntPtr remoteBase, uint sizeOfHeaders)
    {
        Mmv2Native.VirtualProtectEx(hProcess, remoteBase, (UIntPtr)sizeOfHeaders, 0x04, out _);
        byte[] zeros = new byte[sizeOfHeaders];
        WriteRemote(hProcess, remoteBase, zeros, 0, (int)sizeOfHeaders);
    }

    // ------------------------------------------------------------------
    //  Remote memory helpers
    // ------------------------------------------------------------------

    private static IntPtr AllocRemote(IntPtr hProcess, nuint size,
        uint protect = 0x40 /*PAGE_EXECUTE_READWRITE*/)
    {
        IntPtr addr = Mmv2Native.VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)(ulong)size,
            0x1000 | 0x2000, protect);
        if (addr == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"VirtualAllocEx failed (size=0x{size:X}).");
        return addr;
    }

    private static void FreeRemote(IntPtr hProcess, IntPtr addr)
    {
        if (addr != IntPtr.Zero)
            Mmv2Native.VirtualFreeEx(hProcess, addr, UIntPtr.Zero, 0x8000);
    }

    private static unsafe void WriteRemote(IntPtr hProcess, IntPtr dest, byte[] data, int offset, int length)
    {
        if (length == 0) return;
        fixed (byte* p = &data[offset])
        {
            if (!Mmv2Native.WriteProcessMemory(hProcess, dest, p, (UIntPtr)(uint)length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"WriteProcessMemory failed at 0x{dest:X} len=0x{length:X}.");
        }
    }

    private static unsafe void WriteRemoteStruct<T>(IntPtr hProcess, IntPtr dest, T value)
        where T : unmanaged
    {
        if (!Mmv2Native.WriteProcessMemory(hProcess, dest, &value, (UIntPtr)(uint)sizeof(T), out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"WriteProcessMemory<{typeof(T).Name}> failed at 0x{dest:X}.");
    }

    private static unsafe byte[] ReadRemote(IntPtr hProcess, IntPtr src, int length)
    {
        byte[] buf = new byte[length];
        fixed (byte* p = buf)
        {
            if (!Mmv2Native.ReadProcessMemory(hProcess, src, p, (UIntPtr)(uint)length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    $"ReadProcessMemory failed at 0x{src:X} len=0x{length:X}.");
        }
        return buf;
    }

    private static unsafe T ReadRemoteStruct<T>(IntPtr hProcess, IntPtr src)
        where T : unmanaged
    {
        T value = default;
        if (!Mmv2Native.ReadProcessMemory(hProcess, src, &value, (UIntPtr)(uint)sizeof(T), out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"ReadProcessMemory<{typeof(T).Name}> failed at 0x{src:X}.");
        return value;
    }

    private static unsafe void ReadProcessMemory(IntPtr hProcess, IntPtr src, void* buf, int length)
    {
        Mmv2Native.ReadProcessMemory(hProcess, src, buf, (UIntPtr)(uint)length, out _);
    }

    private static unsafe void WriteProcessMemory(IntPtr hProcess, IntPtr dest, void* buf, int length)
    {
        if (!Mmv2Native.WriteProcessMemory(hProcess, dest, buf, (UIntPtr)(uint)length, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                $"WriteProcessMemory failed at 0x{dest:X} len=0x{length:X}.");
    }

    // ------------------------------------------------------------------
    //  String helpers
    // ------------------------------------------------------------------

    private static string NullTermAscii(byte[] buf)
    {
        int len = 0;
        while (len < buf.Length && buf[len] != 0) len++;
        return Encoding.ASCII.GetString(buf, 0, len);
    }

    // ------------------------------------------------------------------
    //  Error factory
    // ------------------------------------------------------------------

    private static ManualMapV2Result Fail(string msg, int code = 0) =>
        new() { Success = false, Message = msg, ErrorCode = code };
}

// ============================================================================
//  P/INVOKE DECLARATIONS (private to this file)
// ============================================================================

internal static class Mmv2Native
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress,
        UIntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
        UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        void* lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        void* lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetModuleHandleA(string? lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr LoadLibraryA(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr lpProcName);

    public static IntPtr GetProcAddressByOrdinal(IntPtr hModule, ushort ordinal) =>
        GetProcAddress(hModule, (IntPtr)(long)(0x8000000000000000UL | ordinal));

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetModuleFileNameW(IntPtr hModule,
        [Out] StringBuilder lpFilename, uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModulesEx(IntPtr hProcess,
        [Out] IntPtr[]? lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule,
        [Out] StringBuilder lpFilename, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Module32FirstW(IntPtr hSnapshot, ref Mmv2_MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Module32NextW(IntPtr hSnapshot, ref Mmv2_MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetProcessId(IntPtr hProcess);
}
