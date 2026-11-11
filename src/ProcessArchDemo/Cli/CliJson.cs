using System.Text.Json;
using ProcessArchDemo.Compat;

namespace ProcessArchDemo.Cli;

internal static class CliJson
{
    public static string Serialize(HostInfo host, IReadOnlyList<CompatibilityReport> reports)
    {
        var payload = new
        {
            schema_version = 1,
            host = new
            {
                arch = host.Architecture.ToWireName(),
                native_machine = host.NativeMachine == 0
                    ? null
                    : $"0x{host.NativeMachine:X4}",
                detection = host.DetectionMethod,
                diagnostic = host.Diagnostic,
            },
            processes = reports.Select(report => new
            {
                pid = report.ProcessId,
                process_name = report.ProcessName,
                image_path = report.ImagePath,
                process_arch = report.ProcessArchitecture.ToWireName(),
                host_arch = report.HostArchitecture.ToWireName(),
                is_wow64 = report.IsWow64,
                running_on_arm = report.RunningOnArm,
                is_arm_native = report.IsArmNative,
                is_emulated = report.IsEmulated,
                confidence = report.Confidence.ToWireName(),
                runtime_machine = report.RuntimeMachine,
                pe_machine = report.PeMachine,
                hybrid_pe_metadata = report.HasHybridPeMetadata,
                hybrid_pe_sections = report.HybridPeSections,
                reason = report.Reason,
            }).ToArray(),
        };

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        return JsonSerializer.Serialize(payload, jsonOptions);
    }
}
