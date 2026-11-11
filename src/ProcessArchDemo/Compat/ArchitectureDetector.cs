using System.ComponentModel;
using System.Diagnostics;

namespace ProcessArchDemo.Compat;

/// <summary>
/// Detects the native host architecture once, then produces compatibility reports for
/// arbitrary PIDs. The detector is safe to reuse for a batch of processes.
/// </summary>
public sealed class ProcessArchitectureDetector
{
    private readonly HostInfo _host;

    public ProcessArchitectureDetector(HostInfo? host = null)
    {
        _host = host ?? DetectHost();
    }

    public HostInfo Host => _host;

    /// <summary>Detects the architecture of the OS, not of the current process.</summary>
    public static HostInfo DetectHost()
    {
        var diagnostics = new List<string>();
        IntPtr currentProcess = NativeMethods.GetCurrentProcess();

        if (NativeMethods.TryIsWow64Process2(
                currentProcess,
                out _,
                out ushort nativeMachine,
                out string? wow64Error))
        {
            HostArchitecture architecture = ArchitectureClassifier.HostFromMachine(nativeMachine);
            if (architecture != HostArchitecture.Unknown)
            {
                return new HostInfo
                {
                    Architecture = architecture,
                    NativeMachine = nativeMachine,
                    DetectionMethod = "IsWow64Process2",
                };
            }

            diagnostics.Add($"IsWow64Process2 returned unsupported native machine 0x{nativeMachine:X4}");
        }
        else if (!string.IsNullOrEmpty(wow64Error))
        {
            diagnostics.Add(wow64Error);
        }

        ushort processorArchitecture = NativeMethods.GetNativeProcessorArchitecture();
        ushort machine = ArchitectureClassifier.MachineFromNativeProcessorArchitecture(processorArchitecture);
        HostArchitecture fallbackArchitecture = ArchitectureClassifier.HostFromMachine(machine);

        return new HostInfo
        {
            Architecture = fallbackArchitecture,
            NativeMachine = machine,
            DetectionMethod = "GetNativeSystemInfo (fallback)",
            Diagnostic = diagnostics.Count == 0 ? null : string.Join("; ", diagnostics),
        };
    }

    public CompatibilityReport Inspect(int processId, string? knownProcessName = null)
    {
        var warnings = new List<string>();
        string? processName = string.IsNullOrWhiteSpace(knownProcessName)
            ? TryGetProcessName(processId)
            : knownProcessName;

        IntPtr handle = NativeMethods.OpenProcess(
            NativeMethods.ProcessQueryLimitedInformation,
            false,
            processId);

        if (handle == IntPtr.Zero)
        {
            string error = NativeMethods.FormatLastError("OpenProcess");
            return BuildReport(
                processId,
                processName,
                imagePath: null,
                processArchitecture: ProcessArchitecture.Unknown,
                isWow64: false,
                confidence: Confidence.Low,
                runtimeMachine: null,
                peMachine: null,
                peInfo: null,
                evidence: new[]
                {
                    $"host={_host.Architecture.ToWireName()}",
                    "runtime=unavailable",
                    "PE=unavailable",
                    $"note={error}",
                });
        }

        bool isWow64 = false;
        bool runtimeExact = false;
        bool hasRuntimeInfo = false;
        ushort processMachine = NativeMethods.ImageFileMachineUnknown;
        ProcessArchitecture runtimeArchitecture = ProcessArchitecture.Unknown;
        string? runtimeMachineText = null;
        string? runtimeApi = null;
        string? imagePath = null;

        try
        {
            if (NativeMethods.TryIsWow64Process2(
                    handle,
                    out processMachine,
                    out _,
                    out string? wow64Error))
            {
                hasRuntimeInfo = true;
                runtimeApi = "IsWow64Process2";
                isWow64 = processMachine != NativeMethods.ImageFileMachineUnknown;
                runtimeMachineText = ArchitectureClassifier.MachineName(processMachine);

                if (processMachine != NativeMethods.ImageFileMachineUnknown)
                {
                    runtimeArchitecture = ArchitectureClassifier.ProcessFromMachine(processMachine);
                    runtimeExact = runtimeArchitecture != ProcessArchitecture.Unknown;
                }
                else if (_host.Architecture is HostArchitecture.X86 or HostArchitecture.X64)
                {
                    // On x86/x64, "not WOW64" means the process is native to the host.
                    runtimeArchitecture = ArchitectureClassifier.ProcessFromHost(_host.Architecture);
                }

                // On an ARM host, ProcessMachine=UNKNOWN is ambiguous: it can mean a
                // native ARM64/ARM64EC/ARM64X process or an x64-emulated process. In
                // that case the PE image is required before claiming an architecture.
            }
            else
            {
                if (!string.IsNullOrEmpty(wow64Error))
                {
                    warnings.Add(wow64Error);
                }

                if (NativeMethods.TryIsWow64Process(handle, out bool legacyWow64, out string? legacyError))
                {
                    hasRuntimeInfo = true;
                    runtimeApi = "IsWow64Process";
                    isWow64 = legacyWow64;
                    runtimeMachineText = legacyWow64 ? "WOW64 (legacy API)" : "not-WOW64 (legacy API)";

                    if (legacyWow64)
                    {
                        // IsWow64Process only says "WOW64", not which emulated
                        // architecture. On x64 hosts this is safely x86; on ARM hosts
                        // the PE image is needed to distinguish x86/ARM32/x64.
                        runtimeArchitecture = _host.Architecture is HostArchitecture.X86 or HostArchitecture.X64
                            ? ProcessArchitecture.X86
                            : ProcessArchitecture.Unknown;
                    }
                    else if (_host.Architecture is HostArchitecture.X86 or HostArchitecture.X64)
                    {
                        runtimeArchitecture = ArchitectureClassifier.ProcessFromHost(_host.Architecture);
                    }
                }
                else if (!string.IsNullOrEmpty(legacyError))
                {
                    warnings.Add(legacyError);
                }
            }

            bool gotPath = NativeMethods.TryGetProcessImagePath(
                handle,
                out imagePath,
                out string? pathError);

            if (!gotPath && !string.IsNullOrEmpty(pathError))
            {
                warnings.Add(pathError);
            }
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }

        if (string.IsNullOrEmpty(imagePath))
        {
            if (NativeMethods.TryGetProcessImagePathWithModuleEnumeration(
                    processId,
                    out imagePath,
                    out string? fallbackError))
            {
                // The fallback succeeded; discard the earlier path warning.
                warnings.RemoveAll(w => w.StartsWith("QueryFullProcessImageNameW", StringComparison.Ordinal));
            }
            else if (!string.IsNullOrEmpty(fallbackError))
            {
                warnings.Add(fallbackError);
            }
        }

        if (processName is null && !string.IsNullOrEmpty(imagePath))
        {
            processName = Path.GetFileNameWithoutExtension(imagePath);
        }

        PeImageInfo peInfo = default;
        bool peRead = false;
        string? peError = null;

        if (!string.IsNullOrEmpty(imagePath))
        {
            peRead = PeImageInspector.TryRead(imagePath, out peInfo, out peError);
            if (!peRead)
            {
                warnings.Add($"PE reader: {peError}");
            }
        }

        ProcessArchitecture rawPeArchitecture = peRead
            ? ArchitectureClassifier.ProcessFromMachine(peInfo.Machine)
            : ProcessArchitecture.Unknown;
        ProcessArchitecture peArchitecture = peRead
            ? ArchitectureClassifier.ClassifyPe(peInfo)
            : ProcessArchitecture.Unknown;

        ProcessArchitecture processArchitecture;
        Confidence confidence;

        if (peArchitecture != ProcessArchitecture.Unknown)
        {
            processArchitecture = peArchitecture;
            confidence = Confidence.High;

            if (runtimeExact &&
                runtimeArchitecture != ProcessArchitecture.Unknown &&
                runtimeArchitecture != peArchitecture &&
                runtimeArchitecture != rawPeArchitecture)
            {
                // The file on disk can have been replaced after the process started.
                confidence = Confidence.Medium;
                warnings.Add(
                    $"runtime machine {ArchitectureClassifier.MachineName(processMachine)} disagrees with image architecture " +
                    $"{peArchitecture.ToWireName()}");
            }
        }
        else if (runtimeArchitecture != ProcessArchitecture.Unknown)
        {
            processArchitecture = runtimeArchitecture;
            confidence = runtimeExact ? Confidence.Medium : Confidence.Low;

            if (!runtimeExact)
            {
                warnings.Add("image architecture unavailable; using runtime WOW64/native evidence only");
            }
        }
        else
        {
            processArchitecture = ProcessArchitecture.Unknown;
            confidence = Confidence.Low;
            warnings.Add("no architecture evidence is available");
        }

        if (peRead &&
            peInfo.Machine is not (
                NativeMethods.ImageFileMachineI386 or
                NativeMethods.ImageFileMachineAmd64 or
                NativeMethods.ImageFileMachineArm or
                NativeMethods.ImageFileMachineThumb or
                NativeMethods.ImageFileMachineArmNt or
                NativeMethods.ImageFileMachineArm64 or
                NativeMethods.ImageFileMachineArm64Ec or
                NativeMethods.ImageFileMachineArm64X))
        {
            warnings.Add($"unsupported image machine 0x{peInfo.Machine:X4}");
        }

        var evidence = new List<string>
        {
            $"host={_host.Architecture.ToWireName()} (native machine 0x{_host.NativeMachine:X4})",
        };

        if (hasRuntimeInfo)
        {
            evidence.Add(
                $"runtime={runtimeMachineText}; wow64={isWow64.ToString().ToLowerInvariant()} [{runtimeApi}]");
        }
        else
        {
            evidence.Add("runtime=unavailable");
        }

        if (peRead)
        {
            string peFact = $"PE={ArchitectureClassifier.MachineName(peInfo.Machine)}";
            if (peInfo.HasHybridMetadata)
            {
                peFact += $"; hybrid-sections={string.Join(',', peInfo.HybridSections)}";
            }

            evidence.Add(peFact);
        }
        else
        {
            evidence.Add(imagePath is null
                ? "PE=unavailable (image path unavailable)"
                : "PE=unavailable (image could not be parsed)");
        }

        evidence.AddRange(warnings.Select(w => $"note={w}"));

        return BuildReport(
            processId,
            processName,
            imagePath,
            processArchitecture,
            isWow64,
            confidence,
            runtimeMachineText,
            peRead ? ArchitectureClassifier.MachineName(peInfo.Machine) : null,
            peRead ? peInfo : null,
            evidence);
    }

    private CompatibilityReport BuildReport(
        int processId,
        string? processName,
        string? imagePath,
        ProcessArchitecture processArchitecture,
        bool isWow64,
        Confidence confidence,
        string? runtimeMachine,
        string? peMachine,
        PeImageInfo? peInfo,
        IReadOnlyList<string> evidence)
    {
        ArmCompatibilityFlags armFlags = ArchitectureClassifier.GetArmFlags(
            _host.Architecture,
            processArchitecture);

        return new CompatibilityReport
        {
            ProcessId = processId,
            ProcessName = processName,
            ImagePath = imagePath,
            HostArchitecture = _host.Architecture,
            ProcessArchitecture = processArchitecture,
            IsWow64 = isWow64,
            RunningOnArm = armFlags.RunningOnArm,
            IsArmNative = armFlags.IsArmNative,
            IsEmulated = armFlags.IsEmulated,
            Confidence = confidence,
            Reason = string.Join("; ", evidence),
            RuntimeMachine = runtimeMachine,
            PeMachine = peMachine,
            HasHybridPeMetadata = peInfo?.HasHybridMetadata ?? false,
            HybridPeSections = peInfo?.HybridSections ?? Array.Empty<string>(),
        };
    }

    private static string? TryGetProcessName(int processId)
    {
        try
        {
            using Process process = Process.GetProcessById(processId);
            return process.ProcessName;
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
        catch (Win32Exception)
        {
            return null;
        }
    }
}
