using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcessArchDemo.Compat;

internal static class NativeMethods
{
    internal const ushort ImageFileMachineUnknown = 0x0000;
    internal const ushort ImageFileMachineI386 = 0x014C;
    internal const ushort ImageFileMachineAmd64 = 0x8664;
    internal const ushort ImageFileMachineArm = 0x01C0;
    internal const ushort ImageFileMachineThumb = 0x01C2;
    internal const ushort ImageFileMachineArmNt = 0x01C4;
    internal const ushort ImageFileMachineArm64 = 0xAA64;
    internal const ushort ImageFileMachineArm64Ec = 0xA641;
    internal const ushort ImageFileMachineArm64X = 0xA64E;

    internal const uint ProcessQueryInformation = 0x0400;
    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const uint ProcessVmRead = 0x0010;

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr process,
        uint flags,
        [Out] StringBuilder executableName,
        ref uint size);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetModuleFileNameExW(
        IntPtr process,
        IntPtr module,
        [Out] StringBuilder filename,
        uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWow64Process2(
        IntPtr process,
        out ushort processMachine,
        out ushort nativeMachine);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWow64Process(
        IntPtr process,
        [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

    [DllImport("kernel32.dll")]
    private static extern void GetNativeSystemInfo(out SystemInfo systemInfo);

    internal static bool TryIsWow64Process2(
        IntPtr process,
        out ushort processMachine,
        out ushort nativeMachine,
        out string? error)
    {
        processMachine = 0;
        nativeMachine = 0;
        error = null;

        try
        {
            if (IsWow64Process2(process, out processMachine, out nativeMachine))
            {
                return true;
            }

            error = FormatLastError("IsWow64Process2");
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            error = "IsWow64Process2 is not available on this Windows version";
            return false;
        }
    }

    internal static bool TryIsWow64Process(IntPtr process, out bool wow64Process, out string? error)
    {
        wow64Process = false;
        error = null;

        try
        {
            if (IsWow64Process(process, out wow64Process))
            {
                return true;
            }

            error = FormatLastError("IsWow64Process");
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            error = "IsWow64Process is not available";
            return false;
        }
    }

    internal static bool TryGetProcessImagePath(IntPtr process, out string? path, out string? error)
    {
        path = null;
        error = null;

        // UNICODE_STRING paths are limited to 32K characters, including the terminator.
        const int bufferLength = 32 * 1024;
        var buffer = new StringBuilder(bufferLength);
        uint size = bufferLength;

        if (QueryFullProcessImageNameW(process, 0, buffer, ref size))
        {
            path = buffer.ToString();
            return path.Length > 0;
        }

        error = FormatLastError("QueryFullProcessImageNameW");
        return false;
    }

    /// <summary>
    /// Fallback for images that cannot be queried with PROCESS_QUERY_LIMITED_INFORMATION.
    /// This requests PROCESS_VM_READ and uses the PSAPI API used by the C++ reference.
    /// </summary>
    internal static bool TryGetProcessImagePathWithModuleEnumeration(
        int processId,
        out string? path,
        out string? error)
    {
        path = null;
        error = null;

        IntPtr process = OpenProcess(
            ProcessQueryInformation | ProcessVmRead,
            false,
            processId);

        if (process == IntPtr.Zero)
        {
            error = FormatLastError("OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)");
            return false;
        }

        try
        {
            if (TryGetProcessImagePath(process, out path, out _))
            {
                return true;
            }

            var buffer = new StringBuilder(32 * 1024);
            uint length = GetModuleFileNameExW(
                process,
                IntPtr.Zero,
                buffer,
                (uint)buffer.Capacity);

            if (length > 0)
            {
                path = buffer.ToString(0, (int)length);
                return path.Length > 0;
            }

            error = FormatLastError("GetModuleFileNameExW");
            return false;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    internal static ushort GetNativeProcessorArchitecture()
    {
        GetNativeSystemInfo(out SystemInfo info);
        return info.ProcessorArchitecture;
    }

    internal static string FormatLastError(string operation)
    {
        int error = Marshal.GetLastWin32Error();
        if (error == 0)
        {
            return $"{operation} failed";
        }

        string message;
        try
        {
            message = new Win32Exception(error).Message;
        }
        catch
        {
            message = "unknown error";
        }

        return $"{operation} failed (Win32 error {error}: {message})";
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SystemInfo
    {
        public ushort ProcessorArchitecture;
        public ushort Reserved;
        public uint PageSize;
        public IntPtr MinimumApplicationAddress;
        public IntPtr MaximumApplicationAddress;
        public IntPtr ActiveProcessorMask;
        public uint NumberOfProcessors;
        public uint ProcessorType;
        public uint AllocationGranularity;
        public ushort ProcessorLevel;
        public ushort ProcessorRevision;
    }
}
