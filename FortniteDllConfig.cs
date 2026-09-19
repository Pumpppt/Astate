namespace Astate;

/// <summary>
/// Configuration holding the 4 configurable DLL paths for Fortnite Client and Host instances.
/// </summary>
public class FortniteDllConfig
{
    /// <summary>
    /// Path to Game Console / Game Client DLL (injected into Fortnite Client instances).
    /// </summary>
    public string? GameConsoleDll { get; set; }

    /// <summary>
    /// Path to Auth DLL (injected into both Fortnite Client and Host instances).
    /// </summary>
    public string? AuthDll { get; set; }

    /// <summary>
    /// Path to Memory Leaks fix DLL (injected into both Fortnite Client and Host instances).
    /// </summary>
    public string? MemoryLeaksDll { get; set; }

    /// <summary>
    /// Path to Gameserver DLL (injected into Fortnite Host instances).
    /// </summary>
    public string? GameserverDll { get; set; }

    public FortniteDllConfig()
    {
    }

    public FortniteDllConfig(
        string? gameConsoleDll = null,
        string? authDll = null,
        string? memoryLeaksDll = null,
        string? gameserverDll = null)
    {
        GameConsoleDll = gameConsoleDll;
        AuthDll = authDll;
        MemoryLeaksDll = memoryLeaksDll;
        GameserverDll = gameserverDll;
    }

    /// <summary>
    /// Returns the ordered list of DLLs to inject into a Client instance:
    /// 1. Game Console / Client DLL
    /// 2. Auth DLL
    /// 3. Memory Leaks DLL
    /// </summary>
    public IEnumerable<string> GetClientDlls()
    {
        if (!string.IsNullOrWhiteSpace(GameConsoleDll))
            yield return GameConsoleDll;

        if (!string.IsNullOrWhiteSpace(AuthDll))
            yield return AuthDll;

        if (!string.IsNullOrWhiteSpace(MemoryLeaksDll))
            yield return MemoryLeaksDll;
    }

    /// <summary>
    /// Returns the ordered list of DLLs to inject into a Host instance:
    /// 1. Auth DLL
    /// 2. Gameserver DLL
    /// 3. Memory Leaks DLL
    /// </summary>
    public IEnumerable<string> GetHostDlls()
    {
        if (!string.IsNullOrWhiteSpace(AuthDll))
            yield return AuthDll;

        if (!string.IsNullOrWhiteSpace(GameserverDll))
            yield return GameserverDll;

        if (!string.IsNullOrWhiteSpace(MemoryLeaksDll))
            yield return MemoryLeaksDll;
    }
}
