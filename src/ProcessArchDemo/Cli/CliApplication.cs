using System.Diagnostics;
using System.Globalization;
using ProcessArchDemo.Compat;

namespace ProcessArchDemo.Cli;

internal static class CliApplication
{
    public static int Run(string[] args)
    {
        Options options;
        try
        {
            options = Options.Parse(args);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            Console.Error.WriteLine("Run with --help for usage.");
            return 2;
        }

        if (options.ShowHelp)
        {
            WriteHelp();
            return 0;
        }

        var detector = new ProcessArchitectureDetector();
        var reports = new List<CompatibilityReport>();

        if (options.All)
        {
            foreach ((int pid, string? name) in EnumerateProcesses(options.NameFilter))
            {
                reports.Add(detector.Inspect(pid, name));
            }
        }
        else
        {
            IReadOnlyList<int> pids = options.ProcessIds.Count == 0
                ? new[] { Environment.ProcessId }
                : options.ProcessIds;

            foreach (int pid in pids)
            {
                reports.Add(detector.Inspect(pid));
            }
        }

        if (options.Json)
        {
            Console.WriteLine(CliJson.Serialize(detector.Host, reports));
        }
        else
        {
            var writer = new TextReportWriter();
            writer.Write(detector.Host, reports, options.Verbose);
        }

        return 0;
    }

    private static IReadOnlyList<(int Pid, string? Name)> EnumerateProcesses(string? nameFilter)
    {
        Process[] processes = Process.GetProcesses();
        var targets = new List<(int Pid, string? Name)>(processes.Length);

        try
        {
            foreach (Process process in processes)
            {
                int pid;
                try
                {
                    pid = process.Id;
                }
                catch (InvalidOperationException)
                {
                    continue;
                }

                string? name = null;
                try
                {
                    name = process.ProcessName;
                }
                catch (InvalidOperationException)
                {
                    // The process exited while it was being enumerated.
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // Keep the PID; the detector will report the access failure.
                }

                if (!string.IsNullOrEmpty(nameFilter) &&
                    (name is null || !name.Contains(nameFilter, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                targets.Add((pid, name));
            }
        }
        finally
        {
            foreach (Process process in processes)
            {
                process.Dispose();
            }
        }

        return targets
            .OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(t => t.Pid)
            .ToList();
    }

    private static void WriteHelp()
    {
        Console.WriteLine(
            """
            ProcessArchDemo - report the execution architecture of Windows processes

            Usage:
              ProcessArchDemo [pid ...] [options]
              ProcessArchDemo --all [--name <filter>] [options]

            Options:
              --all, -a          Inspect every process visible to the current user.
              --name, -n <text>  Filter process names (case-insensitive); implies --all.
              --json             Emit JSON (host information plus one report per process).
              --verbose, -v      Print the detailed block for every process.
              --help, -h         Show this help.

            Examples:
              ProcessArchDemo
              ProcessArchDemo 1234 5678
              ProcessArchDemo --all
              ProcessArchDemo --all --name msedge --json

            Notes:
              is_wow64 is the raw IsWow64Process2 ProcessMachine != UNKNOWN result.
              On ARM64, x64-emulated processes can report ProcessMachine=UNKNOWN,
              so use is_emulated (PE architecture plus ARM host) for emulation.
              On x64, x86 processes are reported as WOW64=true.
            """);
    }

    private sealed class Options
    {
        public List<int> ProcessIds { get; } = new();
        public bool All { get; private set; }
        public bool Json { get; private set; }
        public bool Verbose { get; private set; }
        public bool ShowHelp { get; private set; }
        public string? NameFilter { get; private set; }

        public static Options Parse(string[] args)
        {
            var options = new Options();
            var seenPids = new HashSet<int>();

            for (int i = 0; i < args.Length; i++)
            {
                string argument = args[i];

                switch (argument)
                {
                    case "-h":
                    case "--help":
                    case "/?":
                        options.ShowHelp = true;
                        break;

                    case "-a":
                    case "--all":
                        options.All = true;
                        break;

                    case "--json":
                        options.Json = true;
                        break;

                    case "-v":
                    case "--verbose":
                        options.Verbose = true;
                        break;

                    case "-n":
                    case "--name":
                        if (++i >= args.Length)
                        {
                            throw new ArgumentException($"{argument} requires a value");
                        }

                        options.NameFilter = args[i];
                        break;

                    default:
                        if (argument.StartsWith("--name=", StringComparison.Ordinal))
                        {
                            options.NameFilter = argument["--name=".Length..];
                        }
                        else if (argument.StartsWith("-", StringComparison.Ordinal))
                        {
                            throw new ArgumentException($"unknown option '{argument}'");
                        }
                        else
                        {
                            AddProcessIds(argument, options.ProcessIds, seenPids);
                        }

                        break;
                }
            }

            if (options.NameFilter is not null)
            {
                if (options.NameFilter.Length == 0)
                {
                    throw new ArgumentException("--name requires a non-empty value");
                }

                if (options.ProcessIds.Count > 0)
                {
                    throw new ArgumentException("--name cannot be combined with explicit PIDs");
                }

                options.All = true;
            }

            if (options.All && options.ProcessIds.Count > 0)
            {
                throw new ArgumentException("--all cannot be combined with explicit PIDs");
            }

            return options;
        }

        private static void AddProcessIds(string value, List<int> processIds, HashSet<int> seen)
        {
            foreach (string token in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out int pid) || pid < 0)
                {
                    throw new ArgumentException($"invalid PID '{token}'");
                }

                if (seen.Add(pid))
                {
                    processIds.Add(pid);
                }
            }
        }
    }
}
