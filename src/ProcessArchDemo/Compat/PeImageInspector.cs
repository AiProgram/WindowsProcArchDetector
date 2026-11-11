using System.Text;

namespace ProcessArchDemo.Compat;

internal readonly record struct PeImageInfo(
    ushort Machine,
    bool HasHybridMetadata,
    IReadOnlyList<string> HybridSections);

/// <summary>
/// Minimal PE/COFF header reader. Only the fields needed for architecture detection are
/// parsed; the file is opened with sharing enabled so an executing image can be read.
/// </summary>
internal static class PeImageInspector
{
    private const ushort DosSignature = 0x5A4D;
    private const uint NtSignature = 0x00004550;
    private const int DosHeaderOffsetOfNtHeader = 0x3C;
    private const int FileHeaderSize = 20;
    private const int SectionHeaderSize = 40;

    // ARM64X/CHPE-capable images emitted by the Windows toolchain carry these sections.
    // They are a heuristic: the PE machine type remains the authoritative field.
    private static readonly HashSet<string> HybridSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".a64xrm",
        ".hexpthk",
    };

    public static bool TryRead(string path, out PeImageInfo info, out string? error)
    {
        info = default;
        error = null;

        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                FileOptions.SequentialScan);

            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

            if (stream.Length < DosHeaderOffsetOfNtHeader + sizeof(int))
            {
                error = "file is too small to contain a DOS header";
                return false;
            }

            stream.Position = 0;
            if (reader.ReadUInt16() != DosSignature)
            {
                error = "missing MZ signature";
                return false;
            }

            stream.Position = DosHeaderOffsetOfNtHeader;
            int peOffset = reader.ReadInt32();
            if (peOffset < DosHeaderOffsetOfNtHeader ||
                peOffset + sizeof(uint) + FileHeaderSize > stream.Length)
            {
                error = $"invalid e_lfanew value 0x{peOffset:X8}";
                return false;
            }

            stream.Position = peOffset;
            if (reader.ReadUInt32() != NtSignature)
            {
                error = "missing PE signature";
                return false;
            }

            ushort machine = reader.ReadUInt16();
            ushort numberOfSections = reader.ReadUInt16();
            _ = reader.ReadUInt32(); // TimeDateStamp
            _ = reader.ReadUInt32(); // PointerToSymbolTable
            _ = reader.ReadUInt32(); // NumberOfSymbols
            ushort sizeOfOptionalHeader = reader.ReadUInt16();
            _ = reader.ReadUInt16(); // Characteristics

            if (machine == NativeMethods.ImageFileMachineUnknown)
            {
                error = "PE file has IMAGE_FILE_MACHINE_UNKNOWN";
                return false;
            }

            long sectionTableOffset = (long)peOffset + sizeof(uint) + FileHeaderSize + sizeOfOptionalHeader;
            var hybridSections = new List<string>();
            int sectionCount = Math.Min((int)numberOfSections, 96);

            for (int i = 0; i < sectionCount; i++)
            {
                long sectionOffset = sectionTableOffset + ((long)i * SectionHeaderSize);
                if (sectionOffset + 8 > stream.Length)
                {
                    break;
                }

                stream.Position = sectionOffset;
                byte[] nameBytes = reader.ReadBytes(8);
                string name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

                if (HybridSectionNames.Contains(name) &&
                    !hybridSections.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    hybridSections.Add(name);
                }
            }

            info = new PeImageInfo(machine, hybridSections.Count > 0, hybridSections);
            return true;
        }
        catch (Exception ex) when (
            ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            error = ex.Message;
            return false;
        }
    }
}
