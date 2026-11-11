using System.Buffers.Binary;
using System.Text;

namespace ProcessArchDemo.Tests;

internal static class PeFixtureBuilder
{
    private const int PeOffset = 0x80;
    private const int SectionHeaderSize = 40;

    public static string Write(
        ushort machine,
        ushort optionalHeaderSize = 0,
        params string[] sectionNames)
    {
        int fileSize = PeOffset + 24 + optionalHeaderSize + (sectionNames.Length * SectionHeaderSize);
        var data = new byte[fileSize];

        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0, 2), 0x5A4D);
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3C, 4), PeOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(PeOffset, 4), 0x00004550);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(PeOffset + 4, 2), machine);
        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(PeOffset + 6, 2),
            checked((ushort)sectionNames.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(
            data.AsSpan(PeOffset + 20, 2),
            optionalHeaderSize);

        int sectionTableOffset = PeOffset + 24 + optionalHeaderSize;
        for (int i = 0; i < sectionNames.Length; i++)
        {
            string name = sectionNames[i];
            if (name.Length > 8)
            {
                throw new ArgumentException($"section name '{name}' is longer than 8 characters");
            }

            Encoding.ASCII.GetBytes(name).CopyTo(
                data,
                sectionTableOffset + (i * SectionHeaderSize));
        }

        return WriteRaw(data);
    }

    public static string WriteRaw(byte[] data)
    {
        // Tests run from the build output directory, which is writable both locally
        // and on CI. Avoid assuming that the OS temp directory is writable.
        string directory = Path.Combine(AppContext.BaseDirectory, "pe-fixtures");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, $"{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, data);
        return path;
    }

    public static void Delete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
