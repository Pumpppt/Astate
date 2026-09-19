using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Astate;

/// <summary>
/// Result of a DLL injection attempt.
/// </summary>
public sealed class InjectionResult
{
    public bool Success { get; init; }
    public nint ModuleBase { get; init; }
    public string Message { get; init; } = string.Empty;
    public int ErrorCode { get; init; }
}

/// <summary>
/// Provides standard LoadLibraryA injection into a target remote process.
/// </summary>
public static class DllInjector
{
    private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint MEM_RELEASE = 0x8000;
    private const uint PAGE_READWRITE = 0x04;
    private const uint INFINITE = 0xFFFFFFFF;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualAllocEx(nint hProcess, nint lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(nint hProcess, nint lpAddress, nuint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateRemoteThread(nint hProcess, nint lpThreadAttributes, nuint dwStackSize, nint lpStartAddress, nint lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeThread(nint hThread, out uint lpExitCode);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern nint GetProcAddress(nint hModule, string lpProcName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern nint GetModuleHandle(string lpModuleName);

    /// <summary>
    /// Injects a DLL into a target process using standard LoadLibraryA.
    /// </summary>
    /// <param name="targetProcessId">PID of the target process</param>
    /// <param name="dllPath">Full path to the DLL</param>
    /// <param name="timeoutMs">Timeout in ms to wait for LoadLibrary to complete</param>
    public static InjectionResult Inject(int targetProcessId, string dllPath, uint timeoutMs = 15000)
    {
        if (targetProcessId <= 0)
            return new InjectionResult { Success = false, Message = "Invalid process ID." };

        if (!File.Exists(dllPath))
            return new InjectionResult { Success = false, Message = $"DLL file not found: {dllPath}" };

        string fullDllPath = Path.GetFullPath(dllPath);

        nint hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
        if (hProcess == nint.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return new InjectionResult
            {
                Success = false,
                Message = $"OpenProcess failed (PID {targetProcessId}). Win32 Error: 0x{err:X8}",
                ErrorCode = err
            };
        }

        nint pRemoteMem = nint.Zero;
        nint hThread = nint.Zero;

        try
        {
            nint hKernel32 = GetModuleHandle("kernel32.dll");
            if (hKernel32 == nint.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return new InjectionResult { Success = false, Message = "Could not get handle to kernel32.dll", ErrorCode = err };
            }

            nint pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
            if (pLoadLibrary == nint.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return new InjectionResult { Success = false, Message = "Could not find LoadLibraryA address.", ErrorCode = err };
            }

            byte[] pathBytes = Encoding.ASCII.GetBytes(fullDllPath + "\0");
            pRemoteMem = VirtualAllocEx(hProcess, nint.Zero, (nuint)pathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (pRemoteMem == nint.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return new InjectionResult
                {
                    Success = false,
                    Message = $"VirtualAllocEx failed in target process. Win32 Error: 0x{err:X8}",
                    ErrorCode = err
                };
            }

            if (!WriteProcessMemory(hProcess, pRemoteMem, pathBytes, (nuint)pathBytes.Length, out _))
            {
                int err = Marshal.GetLastWin32Error();
                return new InjectionResult
                {
                    Success = false,
                    Message = $"WriteProcessMemory failed for DLL path. Win32 Error: 0x{err:X8}",
                    ErrorCode = err
                };
            }

            hThread = CreateRemoteThread(hProcess, nint.Zero, 0, pLoadLibrary, pRemoteMem, 0, out uint threadId);
            if (hThread == nint.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return new InjectionResult
                {
                    Success = false,
                    Message = $"CreateRemoteThread failed. Win32 Error: 0x{err:X8}",
                    ErrorCode = err
                };
            }

            WaitForSingleObject(hThread, timeoutMs);

            GetExitCodeThread(hThread, out uint exitCode);
            if (exitCode == 0)
            {
                return new InjectionResult
                {
                    Success = false,
                    Message = "LoadLibraryA returned NULL in target process. Check DLL dependencies and architecture (must match x64 target).",
                    ErrorCode = 0
                };
            }

            return new InjectionResult
            {
                Success = true,
                ModuleBase = (nint)exitCode,
                Message = $"Successfully injected DLL via LoadLibraryA (Module base: 0x{exitCode:X})"
            };
        }
        catch (Exception ex)
        {
            return new InjectionResult
            {
                Success = false,
                Message = $"Injection error: {ex.Message}"
            };
        }
        finally
        {
            if (pRemoteMem != nint.Zero)
            {
                VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            }

            if (hThread != nint.Zero)
            {
                CloseHandle(hThread);
            }

            CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Injects a DLL into a target Process.
    /// </summary>
    public static InjectionResult Inject(Process targetProcess, string dllPath, uint timeoutMs = 15000)
    {
        if (targetProcess == null || targetProcess.HasExited)
            return new InjectionResult { Success = false, Message = "Target process is not running." };

        return Inject(targetProcess.Id, dllPath, timeoutMs);
    }

    /// <summary>
    /// Injects multiple DLLs sequentially into a target process using standard LoadLibraryA.
    /// </summary>
    /// <param name="targetProcessId">PID of the target process</param>
    /// <param name="dllPaths">Collection of DLL paths to inject</param>
    /// <param name="timeoutMs">Timeout in ms for each injection</param>
    /// <returns>A list of <see cref="InjectionResult"/> for each injected DLL.</returns>
    public static List<InjectionResult> InjectMany(int targetProcessId, IEnumerable<string?> dllPaths, uint timeoutMs = 15000)
    {
        var results = new List<InjectionResult>();
        foreach (var path in dllPaths)
        {
            if (string.IsNullOrWhiteSpace(path)) continue;
            results.Add(Inject(targetProcessId, path, timeoutMs));
        }
        return results;
    }

    /// <summary>
    /// Injects multiple DLLs sequentially into a target process using standard LoadLibraryA.
    /// </summary>
    /// <param name="targetProcess">Target Process</param>
    /// <param name="dllPaths">Collection of DLL paths to inject</param>
    /// <param name="timeoutMs">Timeout in ms for each injection</param>
    /// <returns>A list of <see cref="InjectionResult"/> for each injected DLL.</returns>
    public static List<InjectionResult> InjectMany(Process targetProcess, IEnumerable<string?> dllPaths, uint timeoutMs = 15000)
    {
        if (targetProcess == null || targetProcess.HasExited)
            return new List<InjectionResult> { new() { Success = false, Message = "Target process is not running." } };

        return InjectMany(targetProcess.Id, dllPaths, timeoutMs);
    }
}
