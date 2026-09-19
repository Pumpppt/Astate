using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Astate;

/// <summary>
/// Holds the result of launching a full Fortnite session (Client or Host).
/// </summary>
public class FortniteLaunchResult
{
    public Process? ShippingProcess { get; init; }
    public Process? LauncherProcess { get; init; }
    public Process? EacProcess { get; init; }

    /// <summary>
    /// Legacy manual map result (first injected DLL if any).
    /// </summary>
    public ManualMapResult? InjectionResult { get; set; }

    /// <summary>
    /// First ManualMapV2 injection result (for single-DLL compatibility).
    /// </summary>
    public ManualMapV2Result? ManualMapV2Result { get; set; }

    /// <summary>
    /// First standard LoadLibraryA injection result (for single-DLL compatibility).
    /// </summary>
    public InjectionResult? StandardInjectionResult { get; set; }

    /// <summary>
    /// List of all standard injection results for all injected DLLs.
    /// </summary>
    public List<InjectionResult> StandardInjectionResults { get; set; } = new();

    /// <summary>
    /// List of all ManualMapV2 injection results for all injected DLLs.
    /// </summary>
    public List<ManualMapV2Result> ManualMapV2Results { get; set; } = new();

    /// <summary>
    /// Map of DLL path -> Standard InjectionResult.
    /// </summary>
    public Dictionary<string, InjectionResult> InjectionResults { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Map of DLL path -> ManualMapV2Result.
    /// </summary>
    public Dictionary<string, ManualMapV2Result> ManualMapResultsByDll { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public static class LaunchGames
{
    // -------------------------------------------------------------------------
    // Win32 Suspended Process helpers
    // -------------------------------------------------------------------------

    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint NORMAL_PRIORITY_CLASS = 0x00000020;

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize;
        public uint dwXCountChars, dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public nint lpReserved2;
        public nint hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public nint hProcess;
        public nint hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcess(
        string? lpApplicationName,
        string lpCommandLine,
        nint lpProcessAttributes,
        nint lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        nint lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    /// <summary>
    /// Starts a process in a SUSPENDED state and returns the Process handle.
    /// </summary>
    /// <param name="exePath">Full path to the executable.</param>
    /// <param name="args">Command line arguments.</param>
    /// <param name="workingDir">Working directory.</param>
    public static Process? StartSuspended(string exePath, string args = "", string? workingDir = null)
    {
        var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
        string commandLine = $"\"{exePath}\" {args}".Trim();
        string? dir = workingDir ?? Path.GetDirectoryName(exePath);

        bool success = CreateProcess(
            null,
            commandLine,
            nint.Zero,
            nint.Zero,
            false,
            CREATE_SUSPENDED | NORMAL_PRIORITY_CLASS,
            nint.Zero,
            dir,
            ref si,
            out var pi);

        if (!success)
            return null;

        // Wrap in a managed Process from the PID
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        try
        {
            return Process.GetProcessById((int)pi.dwProcessId);
        }
        catch
        {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Path resolution helper
    // -------------------------------------------------------------------------

    private static string ResolveExe(string buildPath, string exeName)
    {
        if (Path.IsPathRooted(exeName) && File.Exists(exeName))
            return exeName;

        // Try FortniteGame/Binaries/Win64 first
        string binPath = Path.Combine(buildPath, "FortniteGame", "Binaries", "Win64", exeName);
        if (File.Exists(binPath)) return binPath;

        // Try directly under buildPath
        string direct = Path.Combine(buildPath, exeName);
        if (File.Exists(direct)) return direct;

        throw new FileNotFoundException($"Executable not found: {exeName}\nSearched in:\n  {binPath}\n  {direct}");
    }

    // -------------------------------------------------------------------------
    // Injection helper
    // -------------------------------------------------------------------------

    private static void PerformDllInjections(
        Process targetProc,
        IEnumerable<string?> dllPaths,
        bool useManualMap,
        FortniteLaunchResult result)
    {
        var validPaths = dllPaths
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (validPaths.Count == 0 || targetProc.HasExited)
            return;

        // Give the process a brief moment to initialize the main module
        Thread.Sleep(1000);

        foreach (var dll in validPaths)
        {
            if (useManualMap)
            {
                var mapRes = ManualMapV2.Inject(targetProc, dll);
                result.ManualMapV2Results.Add(mapRes);
                result.ManualMapResultsByDll[dll] = mapRes;
                result.ManualMapV2Result ??= mapRes;
            }
            else
            {
                var stdRes = DllInjector.Inject(targetProc, dll);
                result.StandardInjectionResults.Add(stdRes);
                result.InjectionResults[dll] = stdRes;
                result.StandardInjectionResult ??= stdRes;
            }
        }
    }

    // -------------------------------------------------------------------------
    // LaunchFortnite (Client)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Launches a Fortnite Client instance.
    /// Injects: Game Console / Client DLL, Auth DLL, and Memory Leaks DLL.
    /// - Shipping.exe  → started normally.
    /// - LauncherExe   → started SUSPENDED immediately.
    /// - EAC exe       → started SUSPENDED immediately.
    /// </summary>
    /// <param name="buildPath">Root directory of the Fortnite installation (containing Engine &amp; FortniteGame).</param>
    /// <param name="shippingExe">Name of the shipping executable, e.g. FortniteClient-Win64-Shipping.exe</param>
    /// <param name="launcherExe">Optional name of the launcher exe, e.g. FortniteLauncher.exe</param>
    /// <param name="eacExe">Optional name of the EAC/BE exe, e.g. FortniteClient-Win64-Shipping_EAC.exe</param>
    /// <param name="version">Version string (informational, passed to args).</param>
    /// <param name="customArgs">Custom arguments. If null, default FortniteArgs() is used.</param>
    /// <param name="username">Optional username for launch args.</param>
    /// <param name="backendHost">Optional backend host address.</param>
    /// <param name="port">Optional port number (default 7777).</param>
    /// <param name="gameConsoleDll">Optional Game Console / Game Client DLL path to inject.</param>
    /// <param name="authDll">Optional Auth DLL path to inject.</param>
    /// <param name="memoryLeaksDll">Optional Memory Leaks fix DLL path to inject.</param>
    /// <param name="dllToInject">Optional fallback / single DLL to inject.</param>
    /// <param name="dllConfig">Optional <see cref="FortniteDllConfig"/> containing all 4 DLL paths.</param>
    /// <param name="mapOptions">Optional manual mapping options (headers clearing, SEH, etc.).</param>
    /// <param name="useManualMap">True to use Manual Map, false to use standard LoadLibraryA.</param>
    /// <returns>A <see cref="FortniteLaunchResult"/> containing all started processes and injection results.</returns>
    public static FortniteLaunchResult LaunchFortnite(
        string buildPath,
        string shippingExe,
        string? launcherExe = null,
        string? eacExe = null,
        string? version = null,
        string? customArgs = null,
        string? username = null,
        string? backendHost = null,
        int port = 7777,
        string? gameConsoleDll = null,
        string? authDll = null,
        string? memoryLeaksDll = null,
        string? dllToInject = null,
        FortniteDllConfig? dllConfig = null,
        ManualMapOptions? mapOptions = null,
        bool useManualMap = false)
    {
        if (string.IsNullOrWhiteSpace(buildPath))
            throw new ArgumentException("Build path cannot be null or empty.", nameof(buildPath));
        if (string.IsNullOrWhiteSpace(shippingExe))
            throw new ArgumentException("Shipping executable name cannot be null or empty.", nameof(shippingExe));

        string shippingFull = ResolveExe(buildPath, shippingExe);
        string workDir = Path.GetDirectoryName(shippingFull) ?? buildPath;

        string finalArgs = customArgs ?? LaunchArgs.FortniteArgs(
            username: username,
            backendHost: backendHost,
            port: port);

        // 1. Start Launcher SUSPENDED (if provided) — must exist before Shipping
        Process? launcherProc = null;
        if (!string.IsNullOrWhiteSpace(launcherExe))
        {
            string launcherFull = ResolveExe(buildPath, launcherExe);
            launcherProc = StartSuspended(launcherFull, workingDir: workDir);
        }

        // 2. Start EAC SUSPENDED (if provided)
        Process? eacProc = null;
        if (!string.IsNullOrWhiteSpace(eacExe))
        {
            string eacFull = ResolveExe(buildPath, eacExe);
            eacProc = StartSuspended(eacFull, workingDir: workDir);
        }

        // 3. Start Shipping normally
        var startInfo = new ProcessStartInfo
        {
            FileName = shippingFull,
            Arguments = finalArgs,
            WorkingDirectory = workDir,
            UseShellExecute = false
        };
        Process? shippingProc = Process.Start(startInfo);

        var result = new FortniteLaunchResult
        {
            ShippingProcess = shippingProc,
            LauncherProcess = launcherProc,
            EacProcess = eacProc
        };

        // 4. Inject Client DLLs: Game Console -> Auth -> Memory Leaks
        if (shippingProc != null)
        {
            var dllsToInject = new List<string?>();

            if (dllConfig != null)
            {
                dllsToInject.AddRange(dllConfig.GetClientDlls());
            }
            else
            {
                dllsToInject.Add(gameConsoleDll ?? dllToInject);
                dllsToInject.Add(authDll);
                dllsToInject.Add(memoryLeaksDll);
            }

            if (!string.IsNullOrWhiteSpace(dllToInject) && !dllsToInject.Contains(dllToInject))
            {
                dllsToInject.Add(dllToInject);
            }

            PerformDllInjections(shippingProc, dllsToInject, useManualMap, result);
        }

        return result;
    }

    // -------------------------------------------------------------------------
    // LaunchFortniteHost (Host / Dedicated Server)
    // -------------------------------------------------------------------------

    /// <summary>
    /// Launches a Fortnite Host / Gameserver instance.
    /// Injects: Auth DLL, Gameserver DLL, and Memory Leaks DLL.
    /// - Shipping.exe  → started with server arguments (-server, -log, -port, etc.).
    /// - LauncherExe   → started SUSPENDED immediately (if specified).
    /// - EAC exe       → started SUSPENDED immediately (if specified).
    /// </summary>
    /// <param name="buildPath">Root directory of the Fortnite installation (containing Engine &amp; FortniteGame).</param>
    /// <param name="shippingExe">Name of the shipping executable, e.g. FortniteClient-Win64-Shipping.exe</param>
    /// <param name="launcherExe">Optional name of the launcher exe, e.g. FortniteLauncher.exe</param>
    /// <param name="eacExe">Optional name of the EAC/BE exe, e.g. FortniteClient-Win64-Shipping_EAC.exe</param>
    /// <param name="version">Version string (informational, passed to args).</param>
    /// <param name="customArgs">Custom arguments. If null, default FortniteHostArgs() is used.</param>
    /// <param name="port">Port number for the game server (default 7777).</param>
    /// <param name="playlist">Optional playlist / game mode (e.g. Playlist_DefaultSolo).</param>
    /// <param name="backendHost">Optional backend host address.</param>
    /// <param name="log">Whether to open the UE4 console log window (-log).</param>
    /// <param name="authDll">Optional Auth DLL path to inject.</param>
    /// <param name="gameserverDll">Optional Gameserver DLL path to inject.</param>
    /// <param name="memoryLeaksDll">Optional Memory Leaks fix DLL path to inject.</param>
    /// <param name="dllToInject">Optional fallback / single DLL to inject.</param>
    /// <param name="dllConfig">Optional <see cref="FortniteDllConfig"/> containing all 4 DLL paths.</param>
    /// <param name="mapOptions">Optional manual mapping options (headers clearing, SEH, etc.).</param>
    /// <param name="useManualMap">True to use Manual Map, false to use standard LoadLibraryA.</param>
    /// <returns>A <see cref="FortniteLaunchResult"/> containing all started processes and injection results.</returns>
    public static FortniteLaunchResult LaunchFortniteHost(
        string buildPath,
        string shippingExe,
        string? launcherExe = null,
        string? eacExe = null,
        string? version = null,
        string? customArgs = null,
        int port = 7777,
        string? playlist = null,
        string? backendHost = null,
        bool log = true,
        string? authDll = null,
        string? gameserverDll = null,
        string? memoryLeaksDll = null,
        string? dllToInject = null,
        FortniteDllConfig? dllConfig = null,
        ManualMapOptions? mapOptions = null,
        bool useManualMap = false)
    {
        if (string.IsNullOrWhiteSpace(buildPath))
            throw new ArgumentException("Build path cannot be null or empty.", nameof(buildPath));
        if (string.IsNullOrWhiteSpace(shippingExe))
            throw new ArgumentException("Shipping executable name cannot be null or empty.", nameof(shippingExe));

        string shippingFull = ResolveExe(buildPath, shippingExe);
        string workDir = Path.GetDirectoryName(shippingFull) ?? buildPath;

        string finalArgs = customArgs ?? LaunchArgs.FortniteHostArgs(
            port: port,
            playlist: playlist,
            log: log,
            backendHost: backendHost);

        // 1. Start Launcher SUSPENDED (if provided)
        Process? launcherProc = null;
        if (!string.IsNullOrWhiteSpace(launcherExe))
        {
            string launcherFull = ResolveExe(buildPath, launcherExe);
            launcherProc = StartSuspended(launcherFull, workingDir: workDir);
        }

        // 2. Start EAC SUSPENDED (if provided)
        Process? eacProc = null;
        if (!string.IsNullOrWhiteSpace(eacExe))
        {
            string eacFull = ResolveExe(buildPath, eacExe);
            eacProc = StartSuspended(eacFull, workingDir: workDir);
        }

        // 3. Start Shipping normally with host args
        var startInfo = new ProcessStartInfo
        {
            FileName = shippingFull,
            Arguments = finalArgs,
            WorkingDirectory = workDir,
            UseShellExecute = false
        };
        Process? shippingProc = Process.Start(startInfo);

        var result = new FortniteLaunchResult
        {
            ShippingProcess = shippingProc,
            LauncherProcess = launcherProc,
            EacProcess = eacProc
        };

        // 4. Inject Host DLLs: Auth -> Gameserver -> Memory Leaks
        if (shippingProc != null)
        {
            var dllsToInject = new List<string?>();

            if (dllConfig != null)
            {
                dllsToInject.AddRange(dllConfig.GetHostDlls());
            }
            else
            {
                dllsToInject.Add(authDll ?? dllToInject);
                dllsToInject.Add(gameserverDll);
                dllsToInject.Add(memoryLeaksDll);
            }

            if (!string.IsNullOrWhiteSpace(dllToInject) && !dllsToInject.Contains(dllToInject))
            {
                dllsToInject.Add(dllToInject);
            }

            PerformDllInjections(shippingProc, dllsToInject, useManualMap, result);
        }

        return result;
    }
}
