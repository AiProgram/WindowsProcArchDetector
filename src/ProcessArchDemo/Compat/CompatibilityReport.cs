namespace ProcessArchDemo.Compat;

/// <summary>Architecture of the Windows host (the native OS architecture).</summary>
public enum HostArchitecture
{
    Unknown,
    X86,
    X64,
    Arm32,
    Arm64,
}

/// <summary>Architecture of a process. Hybrid ARM64 variants are reported separately.</summary>
public enum ProcessArchitecture
{
    Unknown,
    X86,
    X64,
    Arm32,
    Arm64,
    Arm64Ec,
    Arm64X,
}

/// <summary>How much evidence backs a compatibility report.</summary>
public enum Confidence
{
    Low,
    Medium,
    High,
}

/// <summary>Information about the machine/OS that was detected once at startup.</summary>
public sealed record HostInfo
{
    public required HostArchitecture Architecture { get; init; }

    /// <summary>Native machine as an IMAGE_FILE_MACHINE_* value, or 0 when unknown.</summary>
    public ushort NativeMachine { get; init; }

    public required string DetectionMethod { get; init; }

    /// <summary>Optional diagnostic from a failed detection API.</summary>
    public string? Diagnostic { get; init; }
}

/// <summary>
/// One process architecture report. Field names intentionally mirror the C++ module's
/// Report structure (host_arch, process_arch, is_wow64, ...).
/// </summary>
public sealed record CompatibilityReport
{
    public required int ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string? ImagePath { get; init; }

    public required HostArchitecture HostArchitecture { get; init; }
    public required ProcessArchitecture ProcessArchitecture { get; init; }

    public bool IsWow64 { get; init; }
    public bool RunningOnArm { get; init; }
    public bool IsArmNative { get; init; }
    public bool IsEmulated { get; init; }

    public required Confidence Confidence { get; init; }
    public required string Reason { get; init; }

    /// <summary>Raw ProcessMachine value reported by IsWow64Process2, for diagnostics.</summary>
    public string? RuntimeMachine { get; init; }

    /// <summary>IMAGE_FILE_MACHINE_* name read from the image on disk, for diagnostics.</summary>
    public string? PeMachine { get; init; }

    public bool HasHybridPeMetadata { get; init; }
    public IReadOnlyList<string> HybridPeSections { get; init; } = Array.Empty<string>();
}

public static class CompatFormat
{
    public static string ToWireName(this HostArchitecture architecture) => architecture switch
    {
        HostArchitecture.X86 => "x86",
        HostArchitecture.X64 => "x64",
        HostArchitecture.Arm32 => "arm32",
        HostArchitecture.Arm64 => "arm64",
        _ => "unknown",
    };

    public static string ToWireName(this ProcessArchitecture architecture) => architecture switch
    {
        ProcessArchitecture.X86 => "x86",
        ProcessArchitecture.X64 => "x64",
        ProcessArchitecture.Arm32 => "arm32",
        ProcessArchitecture.Arm64 => "arm64",
        ProcessArchitecture.Arm64Ec => "arm64ec",
        ProcessArchitecture.Arm64X => "arm64x",
        _ => "unknown",
    };

    public static string ToWireName(this Confidence confidence) => confidence switch
    {
        Confidence.High => "high",
        Confidence.Medium => "medium",
        _ => "low",
    };

    public static string ToDisplayName(this Confidence confidence) => confidence switch
    {
        Confidence.High => "High",
        Confidence.Medium => "Medium",
        _ => "Low",
    };
}
