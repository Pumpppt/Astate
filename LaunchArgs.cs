namespace Astate;

public static class LaunchArgs
{
    /// <summary>
    /// Builds and returns the launch command line arguments for Fortnite.
    /// Supports options such as custom auth/exchange codes, custom backend, port, and common flags (-epicapp, -epicenv, -fltoken, etc.).
    /// </summary>
    public static string FortniteArgs(
        string? username = null,
        string? password = null,
        string? exchangeCode = null,
        string? backendHost = null,
        int port = 7777,
        bool noEac = true,
        bool noBe = true,
        bool launchChunk = true,
        string? additionalArgs = null)
    {
        var args = new List<string>
        {
            "-epicapp=Fortnite",
            "-epicenv=Prod",
            "-epicportal",
            "-noeac",
            "-nobe",
            "-fltoken=0"
        };

        if (noEac && !args.Contains("-noeac"))
            args.Add("-noeac");

        if (noBe && !args.Contains("-nobe"))
            args.Add("-nobe");

        if (!string.IsNullOrWhiteSpace(username))
        {
            args.Add($"-epicusername=\"{username}\"");
            args.Add($"-epicuserid=\"{username}\"");
        }

        if (!string.IsNullOrWhiteSpace(password))
        {
            args.Add($"-epicpassword=\"{password}\"");
        }

        if (!string.IsNullOrWhiteSpace(exchangeCode))
        {
            args.Add($"-AUTH_LOGIN=unused");
            args.Add($"-AUTH_PASSWORD={exchangeCode}");
            args.Add($"-AUTH_TYPE=exchangecode");
        }

        if (!string.IsNullOrWhiteSpace(backendHost))
        {
            args.Add($"-backend={backendHost}");
            args.Add($"-port={port}");
        }

        if (!string.IsNullOrWhiteSpace(additionalArgs))
        {
            args.Add(additionalArgs);
        }

        return string.Join(" ", args);
    }

    /// <summary>
    /// Builds and returns the launch command line arguments for a Fortnite Server / Host instance.
    /// Supports options such as playlist, port, log console, custom backend, and common server flags.
    /// </summary>
    public static string FortniteHostArgs(
        int port = 7777,
        string? playlist = null,
        bool log = true,
        bool noEac = true,
        bool noBe = true,
        string? backendHost = null,
        string? additionalArgs = null)
    {
        var args = new List<string>
        {
            "-server",
            "-epicapp=Fortnite",
            "-epicenv=Prod",
            "-epicportal",
            "-fltoken=0"
        };

        if (log && !args.Contains("-log"))
            args.Add("-log");

        if (noEac && !args.Contains("-noeac"))
            args.Add("-noeac");

        if (noBe && !args.Contains("-nobe"))
            args.Add("-nobe");

        args.Add($"-port={port}");

        if (!string.IsNullOrWhiteSpace(playlist))
        {
            args.Add($"-playlist={playlist}");
        }

        if (!string.IsNullOrWhiteSpace(backendHost))
        {
            args.Add($"-backend={backendHost}");
        }

        if (!string.IsNullOrWhiteSpace(additionalArgs))
        {
            args.Add(additionalArgs);
        }

        return string.Join(" ", args);
    }

    /// <summary>
    /// Builds and returns launch arguments for Valorant (Riot Client / VALORANT).
    /// </summary>
    public static string ValorantArgs(
        string? launchPatchline = "live",
        string? launchProduct = "valorant",
        string? additionalArgs = null)
    {
        var args = new List<string>
        {
            $"--launch-product={launchProduct}",
            $"--launch-patchline={launchPatchline}"
        };

        if (!string.IsNullOrWhiteSpace(additionalArgs))
        {
            args.Add(additionalArgs);
        }

        return string.Join(" ", args);
    }

    /// <summary>
    /// Builds and returns launch arguments for Rocket League.
    /// </summary>
    public static string RocketLeagueArgs(
        string? authTicket = null,
        bool noIntro = false,
        string? additionalArgs = null)
    {
        var args = new List<string>();

        if (noIntro)
        {
            args.Add("-nomovie");
        }

        if (!string.IsNullOrWhiteSpace(authTicket))
        {
            args.Add($"-EpicPortal -auth_ticket={authTicket}");
        }

        if (!string.IsNullOrWhiteSpace(additionalArgs))
        {
            args.Add(additionalArgs);
        }

        return string.Join(" ", args);
    }
}
