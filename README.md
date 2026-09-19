# Astate — Fortnite Launcher & Multi-DLL Injector Library

A modern .NET library designed for launching and injecting custom modules into Fortnite **Client** and **Host / Gameserver** instances.

---

##  Table of Contents

1. [Features](#features)
2. [How It Works](#how-it-works)
3. [The 4-DLL Architecture](#the-4-dll-architecture)
4. [Adding Astate to Your Project](#adding-astate-to-your-project)
5. [Quick Start Code Examples](#quick-start-code-examples)
   - [1. Configuring the 4 DLLs](#1-configuring-the-4-dlls)
   - [2. Launching a Client Instance](#2-launching-a-client-instance)
   - [3. Launching a Host / Server Instance](#3-launching-a-host--server-instance)
6. [GUI App Integration Example (WPF / WinForms / Avalonia)](#gui-app-integration-example)
7. [API Reference Summary](#api-reference-summary)

---

##  Features

- **Dual Launch Modes**:
  - **Client**: Starts suspended EAC/Launcher processes, launches Fortnite Shipping exe with client arguments, and injects client DLLs.
  - **Host / Gameserver**: Launches the shipping binary with server parameters (`-server`, `-log`, `-port`, `-playlist`) and injects server-specific DLLs.
- **4-Line Configurable DLL System**:
  - `GameConsoleDll`: Game Console / Client hook DLL.
  - `AuthDll`: Auth bypass / backend redirection DLL.
  - `MemoryLeaksDll`: Memory leak patch DLL.
  - `GameserverDll`: Gameserver logic DLL.
- **Dual Injection Engines**:
  - **Standard Injection**: High-compatibility `LoadLibraryA` via remote thread execution.
  - **ManualMapV2**: Advanced PE loader manual mapper with import resolution, relocations, and optional header erasing.
- **Detailed Injection Diagnostics**: Per-DLL success status, module base addresses, and error messages.

---

##  The 4-DLL Architecture

When launching either a **Client** or a **Host**, `Astate` injects the corresponding DLLs in order:

| DLL Slot | Target Instances | Description |
| :--- | :--- | :--- |
| **`GameConsoleDll`** | **Client** | Game console unlocker / Client mods |
| **`AuthDll`** | **Client** & **Host** | Custom backend / auth redirector |
| **`MemoryLeaksDll`** | **Client** & **Host** | Engine memory leak fix patches |
| **`GameserverDll`** | **Host** | Server gameplay / netcode modules |

### Injection Matrix

- **Client (`LaunchFortnite`)**:
  1. `GameConsoleDll`
  2. `AuthDll`
  3. `MemoryLeaksDll`

- **Host (`LaunchFortniteHost`)**:
  1. `AuthDll`
  2. `GameserverDll`
  3. `MemoryLeaksDll`

---

##  Adding Astate to Your Project

### Option A: Project Reference (Recommended)

In your solution, add a project reference to `Astate.csproj`:

```xml
<ItemGroup>
  <ProjectReference Include="..\Astate\Astate.csproj" />
</ItemGroup>
```

Or via .NET CLI:
```bash
dotnet add YourApp/YourApp.csproj reference Astate/Astate.csproj
```

### Option B: Direct DLL Reference

Build `Astate` (`dotnet build -c Release`), then reference `Astate.dll`:

```xml
<ItemGroup>
  <Reference Include="Astate">
    <HintPath>..\path\to\Astate.dll</HintPath>
  </Reference>
</ItemGroup>
```

---

##  Quick Start Code Examples

### 1. Configuring the 4 DLLs

```csharp
using Astate;

var dllConfig = new FortniteDllConfig
{
    GameConsoleDll = @"C:\Modding\DLLs\Console.dll",
    AuthDll        = @"C:\Modding\DLLs\Auth.dll",
    MemoryLeaksDll = @"C:\Modding\DLLs\MemoryLeaks.dll",
    GameserverDll  = @"C:\Modding\DLLs\Gameserver.dll"
};
```

---

### 2. Launching a Client Instance

```csharp
using Astate;

string buildPath = @"C:\Games\Fortnite_Build";
string shippingExe = "FortniteClient-Win64-Shipping.exe";
string launcherExe = "FortniteLauncher.exe";
string eacExe      = "FortniteClient-Win64-Shipping_EAC.exe";

FortniteLaunchResult result = LaunchGames.LaunchFortnite(
    buildPath: buildPath,
    shippingExe: shippingExe,
    launcherExe: launcherExe,
    eacExe: eacExe,
    username: "Player1",
    backendHost: "127.0.0.1",
    port: 7777,
    dllConfig: dllConfig,
    useManualMap: false // Set to true to use ManualMapV2
);

// Inspect results
if (result.ShippingProcess != null)
{
    Console.WriteLine($"Shipping process started with PID: {result.ShippingProcess.Id}");
    
    foreach (var (dllPath, injectRes) in result.InjectionResults)
    {
        Console.WriteLine($"DLL: {Path.GetFileName(dllPath)} -> Success: {injectRes.Success} (Message: {injectRes.Message})");
    }
}
```

---

### 3. Launching a Host / Server Instance

```csharp
using Astate;

string buildPath = @"C:\Games\Fortnite_Build";
string shippingExe = "FortniteClient-Win64-Shipping.exe";

FortniteLaunchResult result = LaunchGames.LaunchFortniteHost(
    buildPath: buildPath,
    shippingExe: shippingExe,
    port: 7777,
    playlist: "Playlist_DefaultSolo",
    log: true, // Opens Unreal Engine -log console window
    dllConfig: dllConfig,
    useManualMap: false
);

// Inspect results
if (result.ShippingProcess != null)
{
    Console.WriteLine($"Host Server started with PID: {result.ShippingProcess.Id}");
    
    foreach (var (dllPath, injectRes) in result.InjectionResults)
    {
        Console.WriteLine($"Host DLL: {Path.GetFileName(dllPath)} -> Injected: {injectRes.Success}");
    }
}
```

---

##  GUI App Integration Example

Here is a practical integration pattern for a launcher UI (WPF / WinForms / Avalonia / MAUI):

### Step 1: Model for App Settings

```csharp
public class LauncherSettings
{
    public string FortnitePath { get; set; } = @"C:\Fortnite";
    public string Username { get; set; } = "Player";
    public string BackendIp { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 7777;
    public bool UseManualMap { get; set; } = false;

    // 4 DLL Paths
    public string GameConsoleDll { get; set; } = string.Empty;
    public string AuthDll { get; set; } = string.Empty;
    public string MemoryLeaksDll { get; set; } = string.Empty;
    public string GameserverDll { get; set; } = string.Empty;
}
```

### Step 2: Launcher Controller / Service

```csharp
using System.IO;
using System.Threading.Tasks;
using Astate;

public class LauncherService
{
    public async Task<FortniteLaunchResult> StartClientAsync(LauncherSettings settings)
    {
        return await Task.Run(() =>
        {
            var dllConfig = new FortniteDllConfig(
                gameConsoleDll: settings.GameConsoleDll,
                authDll: settings.AuthDll,
                memoryLeaksDll: settings.MemoryLeaksDll,
                gameserverDll: settings.GameserverDll
            );

            return LaunchGames.LaunchFortnite(
                buildPath: settings.FortnitePath,
                shippingExe: "FortniteClient-Win64-Shipping.exe",
                launcherExe: "FortniteLauncher.exe",
                eacExe: "FortniteClient-Win64-Shipping_EAC.exe",
                username: settings.Username,
                backendHost: settings.BackendIp,
                port: settings.Port,
                dllConfig: dllConfig,
                useManualMap: settings.UseManualMap
            );
        });
    }

    public async Task<FortniteLaunchResult> StartHostAsync(LauncherSettings settings, string playlist = "Playlist_DefaultSolo")
    {
        return await Task.Run(() =>
        {
            var dllConfig = new FortniteDllConfig(
                gameConsoleDll: settings.GameConsoleDll,
                authDll: settings.AuthDll,
                memoryLeaksDll: settings.MemoryLeaksDll,
                gameserverDll: settings.GameserverDll
            );

            return LaunchGames.LaunchFortniteHost(
                buildPath: settings.FortnitePath,
                shippingExe: "FortniteClient-Win64-Shipping.exe",
                port: settings.Port,
                playlist: playlist,
                log: true,
                dllConfig: dllConfig,
                useManualMap: settings.UseManualMap
            );
        });
    }
}
```

### Step 3: Button Click Event Handlers (UI)

```csharp
private async void OnLaunchClientClicked(object sender, EventArgs e)
{
    SetControlsEnabled(false);
    StatusLabel.Text = "Launching Client and injecting DLLs...";

    try
    {
        var result = await _launcherService.StartClientAsync(_currentSettings);
        
        if (result.ShippingProcess != null)
        {
            StatusLabel.Text = $"Client running (PID {result.ShippingProcess.Id})";
        }
        else
        {
            StatusLabel.Text = "Failed to launch client executable.";
        }
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Launch Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
    finally
    {
        SetControlsEnabled(true);
    }
}

private async void OnLaunchHostClicked(object sender, EventArgs e)
{
    SetControlsEnabled(false);
    StatusLabel.Text = "Launching Host Server and injecting DLLs...";

    try
    {
        var result = await _launcherService.StartHostAsync(_currentSettings);

        if (result.ShippingProcess != null)
        {
            StatusLabel.Text = $"Host Server running (PID {result.ShippingProcess.Id})";
        }
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Host Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
    finally
    {
        SetControlsEnabled(true);
    }
}
```

---

##  API Reference Summary

### `FortniteDllConfig`
- `GameConsoleDll` (`string?`): Path to Console / Client DLL.
- `AuthDll` (`string?`): Path to Auth DLL.
- `MemoryLeaksDll` (`string?`): Path to Memory Leaks patch DLL.
- `GameserverDll` (`string?`): Path to Gameserver DLL.
- `GetClientDlls()`: Returns enumerable of Client DLL paths in injection order.
- `GetHostDlls()`: Returns enumerable of Host DLL paths in injection order.

### `LaunchGames`
- `LaunchFortnite(...)`: Starts client session, EAC/Launcher suspended, injects `GameConsoleDll`, `AuthDll`, `MemoryLeaksDll`.
- `LaunchFortniteHost(...)`: Starts server session with `-server -log`, injects `AuthDll`, `GameserverDll`, `MemoryLeaksDll`.
- `StartSuspended(exePath, args, workingDir)`: Low-level Win32 suspended process launcher.

### `LaunchArgs`
- `FortniteArgs(...)`: Generates client arguments (`-epicapp=Fortnite`, `-noeac`, `-nobe`, `-fltoken=0`, `-epicusername`, `-backend`, etc.).
- `FortniteHostArgs(...)`: Generates host arguments (`-server`, `-log`, `-port`, `-playlist`, `-noeac`, `-nobe`, `-fltoken=0`, etc.).

### `DllInjector`
- `Inject(targetProcessId, dllPath, timeoutMs)`: Injects a single DLL via standard `LoadLibraryA`.
- `Inject(targetProcess, dllPath, timeoutMs)`: Injects a single DLL into a `Process` object.
- `InjectMany(targetProcess, dllPaths, timeoutMs)`: Injects a collection of DLLs sequentially.

### `ManualMapV2`
- `Inject(targetProcess, dllPath, options)`: Manual-maps a DLL directly into remote process memory without `LoadLibraryA`.
