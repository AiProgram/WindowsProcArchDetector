using System.Globalization;
using ProcessArchDemo.Compat;

namespace ProcessArchDemo.Cli;

internal sealed class TextReportWriter
{
    public void Write(HostInfo host, IReadOnlyList<CompatibilityReport> reports, bool verbose)
    {
        Console.WriteLine($"Host architecture : {host.Architecture.ToWireName()}");

        string nativeMachine = host.NativeMachine == 0
            ? "unknown"
            : $"0x{host.NativeMachine:X4}";
        Console.WriteLine($"Host detection    : {host.DetectionMethod} (native machine {nativeMachine})");

        if (!string.IsNullOrWhiteSpace(host.Diagnostic))
        {
            Console.WriteLine($"Host note         : {host.Diagnostic}");
        }

        Console.WriteLine();

        if (reports.Count == 0)
        {
            Console.WriteLine("No matching processes.");
            return;
        }

        if (reports.Count == 1 || verbose)
        {
            foreach (CompatibilityReport report in reports)
            {
                WriteDetailed(report);
                Console.WriteLine();
            }

            if (reports.Count > 1)
            {
                WriteSummary(reports);
            }

            return;
        }

        WriteTable(reports);
        Console.WriteLine();
        WriteSummary(reports);
        Console.WriteLine("Use --verbose or --json for full evidence.");
    }

    private static void WriteDetailed(CompatibilityReport report)
    {
        Console.WriteLine($"PID {report.ProcessId} ({report.ProcessName ?? "unknown"})");
        WriteField("host_arch", report.HostArchitecture.ToWireName());
        WriteField("process_arch", report.ProcessArchitecture.ToWireName());
        WriteField("is_wow64", FormatBool(report.IsWow64));
        WriteField("running_on_arm", FormatBool(report.RunningOnArm));
        WriteField("is_arm_native", FormatBool(report.IsArmNative));
        WriteField("is_emulated", FormatBool(report.IsEmulated));
        WriteField("confidence", report.Confidence.ToWireName());
        WriteField("runtime_machine", report.RuntimeMachine ?? "unavailable");
        WriteField("pe_machine", report.PeMachine ?? "unavailable");
        WriteField(
            "hybrid_pe",
            report.HasHybridPeMetadata
                ? $"true ({string.Join(", ", report.HybridPeSections)})"
                : "false");
        WriteField("image_path", report.ImagePath ?? "(unavailable)");
        WriteField("reason", report.Reason);
    }

    private static void WriteTable(IReadOnlyList<CompatibilityReport> reports)
    {
        int pidWidth = Math.Max(3, reports.Max(r => r.ProcessId.ToString(CultureInfo.InvariantCulture).Length));
        int nameWidth = Math.Clamp(reports.Max(r => (r.ProcessName ?? "?").Length), 7, 30);
        int archWidth = Math.Max(4, reports.Max(r => r.ProcessArchitecture.ToWireName().Length));

        Console.WriteLine(
            $"{Fit("PID", pidWidth)}  " +
            $"{Fit("Process", nameWidth)}  " +
            $"{Fit("Arch", archWidth)}  " +
            $"{Fit("WOW64", 5)}  " +
            $"{Fit("ARM-native", 10)}  " +
            $"{Fit("Emulated", 8)}  " +
            "Confidence");

        Console.WriteLine(
            $"{new string('-', pidWidth)}  " +
            $"{new string('-', nameWidth)}  " +
            $"{new string('-', archWidth)}  " +
            $"{new string('-', 5)}  " +
            $"{new string('-', 10)}  " +
            $"{new string('-', 8)}  " +
            new string('-', 10));

        foreach (CompatibilityReport report in reports)
        {
            Console.WriteLine(
                $"{Fit(report.ProcessId.ToString(CultureInfo.InvariantCulture), pidWidth)}  " +
                $"{Fit(report.ProcessName ?? "?", nameWidth)}  " +
                $"{Fit(report.ProcessArchitecture.ToWireName(), archWidth)}  " +
                $"{Fit(FormatBool(report.IsWow64), 5)}  " +
                $"{Fit(FormatBool(report.IsArmNative), 10)}  " +
                $"{Fit(FormatBool(report.IsEmulated), 8)}  " +
                report.Confidence.ToWireName());
        }
    }

    private static void WriteSummary(IReadOnlyList<CompatibilityReport> reports)
    {
        string[] order = { "arm64", "arm64ec", "arm64x", "x64", "x86", "arm32", "unknown" };
        var counts = reports
            .GroupBy(r => r.ProcessArchitecture.ToWireName())
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

        string summary = string.Join(
            ", ",
            order
                .Where(architecture => counts.ContainsKey(architecture))
                .Select(architecture => $"{architecture}={counts[architecture]}"));

        Console.WriteLine($"Summary: {reports.Count} process(es); {summary}");
    }

    private static void WriteField(string name, string value)
    {
        Console.WriteLine($"  {name,-18}: {value}");
    }

    private static string FormatBool(bool value) => value ? "true" : "false";

    private static string Fit(string value, int width)
    {
        if (value.Length > width)
        {
            return width <= 3
                ? value[..width]
                : string.Concat(value.AsSpan(0, width - 3), "...");
        }

        return value.PadRight(width);
    }
}
