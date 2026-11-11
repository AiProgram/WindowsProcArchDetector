namespace ProcessArchDemo.Compat;

internal readonly record struct ArmCompatibilityFlags(
    bool RunningOnArm,
    bool IsArmNative,
    bool IsEmulated);

/// <summary>
/// Pure architecture mapping rules. Kept separate from the Win32 probing code so the
/// mappings can be exercised without touching a live process or Windows SDK headers.
/// </summary>
internal static class ArchitectureClassifier
{
    public static HostArchitecture HostFromMachine(ushort machine) => machine switch
    {
        NativeMethods.ImageFileMachineI386 => HostArchitecture.X86,
        NativeMethods.ImageFileMachineAmd64 => HostArchitecture.X64,
        NativeMethods.ImageFileMachineArm or
            NativeMethods.ImageFileMachineThumb or
            NativeMethods.ImageFileMachineArmNt => HostArchitecture.Arm32,
        NativeMethods.ImageFileMachineArm64 => HostArchitecture.Arm64,
        _ => HostArchitecture.Unknown,
    };

    public static ProcessArchitecture ProcessFromMachine(ushort machine) => machine switch
    {
        NativeMethods.ImageFileMachineI386 => ProcessArchitecture.X86,
        NativeMethods.ImageFileMachineAmd64 => ProcessArchitecture.X64,
        NativeMethods.ImageFileMachineArm or
            NativeMethods.ImageFileMachineThumb or
            NativeMethods.ImageFileMachineArmNt => ProcessArchitecture.Arm32,
        NativeMethods.ImageFileMachineArm64 => ProcessArchitecture.Arm64,
        NativeMethods.ImageFileMachineArm64Ec => ProcessArchitecture.Arm64Ec,
        NativeMethods.ImageFileMachineArm64X => ProcessArchitecture.Arm64X,
        _ => ProcessArchitecture.Unknown,
    };

    public static ProcessArchitecture ProcessFromHost(HostArchitecture architecture) => architecture switch
    {
        HostArchitecture.X86 => ProcessArchitecture.X86,
        HostArchitecture.X64 => ProcessArchitecture.X64,
        HostArchitecture.Arm32 => ProcessArchitecture.Arm32,
        HostArchitecture.Arm64 => ProcessArchitecture.Arm64,
        _ => ProcessArchitecture.Unknown,
    };

    public static ProcessArchitecture ClassifyPe(PeImageInfo info)
    {
        ProcessArchitecture architecture = ProcessFromMachine(info.Machine);
        if (!info.HasHybridMetadata)
        {
            return architecture;
        }

        // Hybrid section markers refine the machine field. Some ARM64EC images are
        // stamped AMD64; ARM64X images can be stamped ARM64.
        if (info.Machine == NativeMethods.ImageFileMachineAmd64)
        {
            return ProcessArchitecture.Arm64Ec;
        }

        if (info.Machine == NativeMethods.ImageFileMachineArm64)
        {
            return ProcessArchitecture.Arm64X;
        }

        return architecture;
    }

    public static ushort MachineFromNativeProcessorArchitecture(ushort processorArchitecture) =>
        processorArchitecture switch
        {
            0 => NativeMethods.ImageFileMachineI386,   // PROCESSOR_ARCHITECTURE_INTEL
            5 => NativeMethods.ImageFileMachineArmNt,  // PROCESSOR_ARCHITECTURE_ARM
            9 => NativeMethods.ImageFileMachineAmd64,  // PROCESSOR_ARCHITECTURE_AMD64
            12 => NativeMethods.ImageFileMachineArm64, // PROCESSOR_ARCHITECTURE_ARM64
            _ => NativeMethods.ImageFileMachineUnknown,
        };

    public static string MachineName(ushort machine) => machine switch
    {
        NativeMethods.ImageFileMachineI386 => "I386",
        NativeMethods.ImageFileMachineAmd64 => "AMD64",
        NativeMethods.ImageFileMachineArm => "ARM",
        NativeMethods.ImageFileMachineThumb => "THUMB",
        NativeMethods.ImageFileMachineArmNt => "ARMNT",
        NativeMethods.ImageFileMachineArm64 => "ARM64",
        NativeMethods.ImageFileMachineArm64Ec => "ARM64EC",
        NativeMethods.ImageFileMachineArm64X => "ARM64X",
        NativeMethods.ImageFileMachineUnknown => "unknown",
        _ => $"0x{machine:X4}",
    };

    public static ArmCompatibilityFlags GetArmFlags(
        HostArchitecture host,
        ProcessArchitecture process)
    {
        bool runningOnArm = host is HostArchitecture.Arm64 or HostArchitecture.Arm32;
        bool isArmNative = host switch
        {
            HostArchitecture.Arm64 => process is
                ProcessArchitecture.Arm64 or ProcessArchitecture.Arm64Ec or ProcessArchitecture.Arm64X,
            HostArchitecture.Arm32 => process is ProcessArchitecture.Arm32,
            _ => false,
        };
        bool isEmulated = runningOnArm &&
                          !isArmNative &&
                          process is
                              ProcessArchitecture.X86 or
                              ProcessArchitecture.X64 or
                              ProcessArchitecture.Arm32;

        return new ArmCompatibilityFlags(runningOnArm, isArmNative, isEmulated);
    }
}
