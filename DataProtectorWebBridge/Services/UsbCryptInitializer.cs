using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace DataProtectorWebBridge.Services
{
    internal sealed class UsbCryptInitializer
    {
        private const int MetadataBytes = 512;
        private const long MetadataOffsetBytes = 64L * 1024L;
        private const int MetadataDeviceIdBytes = 128;
        private const int MetadataVersionBytes = 64;
        private const int MetadataSha256Bytes = 64;
        private const int MetadataReservedBytes = 92;
        private const int PasswordSaltBytes = 16;
        private const int PasswordVerifierBytes = 32;
        private const int ManifestKeyBytes = 64;
        private const int KdfBytes = PasswordVerifierBytes + ManifestKeyBytes;
        private const int DefaultKeyBytes = 32;
        private const int KdfIterations = 200000;
        private const uint MetadataMagic = 0x32535544u;
        private const uint MetadataVersion = 2;
        private const uint AlgorithmRc4 = 1;
        private const string RuntimeDirectoryName = "DataProtectorUsbRuntime";
        private const string ToolFileName = "DataProtectorUsbTool.exe";
        private const string DriverFileName = "DataProtectorUsbCrypt.sys";
        private static readonly Encoding Utf16NoBom = new UnicodeEncoding(false, false, true);

        private readonly RemovableDeviceInventory inventory = new RemovableDeviceInventory();

        public UsbCryptInitializationResult Initialize(UsbCryptInitializationRequest request, string agentDirectory, Uri serverBaseUri)
        {
            UsbCryptInitializationRequest normalized = NormalizeRequest(request);
            CentralPolicyStore.RemovableDeviceObservation target = ResolveTarget(normalized.hardwareId);
            string targetRoot = NormalizeDriveRoot(target.driveLetter);
            if (string.IsNullOrWhiteSpace(targetRoot) || !Directory.Exists(targetRoot))
            {
                throw new InvalidOperationException("Target removable device is not mounted with a writable public drive letter.");
            }

            PhysicalDiskTarget disk = ResolvePhysicalDiskTarget(targetRoot);
            ValidateMetadataGap(disk, normalized.publicToolAreaBytes);

            if (!normalized.confirmed)
            {
                return BuildDryRun(normalized, target, targetRoot, disk);
            }

            if (serverBaseUri == null)
            {
                throw new InvalidOperationException("Agent server URL is required to download the USB crypt runtime package.");
            }

            byte[] key = new byte[DefaultKeyBytes];
            string extractionRoot = Path.Combine(Path.GetTempPath(), "DataProtectorUsbCrypt-" + Guid.NewGuid().ToString("N"));
            try
            {
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(key);
                }

                UsbRuntimePackage runtimePackage = DownloadAndExtractRuntimePackage(normalized, serverBaseUri, extractionRoot);
                PreparePublicToolArea(targetRoot, runtimePackage);

                long dataLength = normalized.dataLengthBytes > 0
                    ? normalized.dataLengthBytes
                    : Math.Max(0, disk.diskSizeBytes - normalized.publicToolAreaBytes);

                byte[] metadata = BuildRawMetadata(normalized, target, key, dataLength);
                WriteRawMetadata(disk.physicalDrivePath, metadata);

                return new UsbCryptInitializationResult
                {
                    hardwareId = target.hardwareId,
                    driveLetter = target.driveLetter,
                    volumeGuid = target.volumeGuid,
                    publicToolAreaBytes = normalized.publicToolAreaBytes,
                    dataOffsetBytes = normalized.publicToolAreaBytes,
                    dataLengthBytes = dataLength,
                    metadataOffsetBytes = MetadataOffsetBytes,
                    metadataLocation = disk.physicalDrivePath + "@" + MetadataOffsetBytes,
                    toolPath = Path.Combine(targetRoot, ToolFileName),
                    driverPath = Path.Combine(targetRoot, RuntimeDirectoryName),
                    driverPackageVersion = normalized.driverPackageVersion,
                    driverPackageSha256 = normalized.driverPackageSha256,
                    dryRun = false,
                    initialized = true,
                    message = "USB runtime package was copied and hidden; unlock metadata was written to the raw disk metadata sector."
                };
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
                DeleteDirectorySafe(extractionRoot);
            }
        }

        private UsbCryptInitializationResult BuildDryRun(
            UsbCryptInitializationRequest request,
            CentralPolicyStore.RemovableDeviceObservation target,
            string targetRoot,
            PhysicalDiskTarget disk)
        {
            long dataLength = request.dataLengthBytes > 0
                ? request.dataLengthBytes
                : Math.Max(0, disk.diskSizeBytes - request.publicToolAreaBytes);

            return new UsbCryptInitializationResult
            {
                hardwareId = target.hardwareId,
                driveLetter = target.driveLetter,
                volumeGuid = target.volumeGuid,
                publicToolAreaBytes = request.publicToolAreaBytes,
                dataOffsetBytes = request.publicToolAreaBytes,
                dataLengthBytes = dataLength,
                metadataOffsetBytes = MetadataOffsetBytes,
                metadataLocation = disk.physicalDrivePath + "@" + MetadataOffsetBytes,
                toolPath = Path.Combine(targetRoot, ToolFileName),
                driverPath = Path.Combine(targetRoot, RuntimeDirectoryName),
                driverPackageVersion = request.driverPackageVersion,
                driverPackageSha256 = request.driverPackageSha256,
                dryRun = true,
                initialized = false,
                message = "USB initialization dry run succeeded. Submit confirmed=true to download the runtime package and write raw disk metadata."
            };
        }

        private CentralPolicyStore.RemovableDeviceObservation ResolveTarget(string hardwareId)
        {
            CentralPolicyStore.RemovableDeviceObservation[] devices = inventory.Snapshot();
            CentralPolicyStore.RemovableDeviceObservation target = devices.FirstOrDefault(device =>
                device != null &&
                string.Equals(device.hardwareId, hardwareId, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(device.driveLetter));
            if (target == null)
            {
                throw new InvalidOperationException("Target removable hardware id is not online on this agent.");
            }

            return target;
        }

        private UsbRuntimePackage DownloadAndExtractRuntimePackage(UsbCryptInitializationRequest request, Uri serverBaseUri, string extractionRoot)
        {
            Uri downloadUri = BuildPackageUri(serverBaseUri, request.driverPackageDownloadPath);
            byte[] packageBytes;
            using (WebClient client = new WebClient())
            {
                packageBytes = client.DownloadData(downloadUri);
            }

            string actualSha256 = ComputeSha256Hex(packageBytes);
            if (!string.Equals(actualSha256, request.driverPackageSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("USB crypt runtime package SHA256 mismatch.");
            }

            Directory.CreateDirectory(extractionRoot);
            ExtractZipSafely(packageBytes, extractionRoot);

            string toolPath = Directory
                .GetFiles(extractionRoot, ToolFileName, SearchOption.AllDirectories)
                .FirstOrDefault();
            if (string.IsNullOrWhiteSpace(toolPath))
            {
                throw new InvalidOperationException("USB crypt runtime package does not contain DataProtectorUsbTool.exe.");
            }

            string driverFile = Directory
                .GetFiles(extractionRoot, DriverFileName, SearchOption.AllDirectories)
                .FirstOrDefault();
            if (string.IsNullOrWhiteSpace(driverFile))
            {
                throw new InvalidOperationException("USB crypt runtime package does not contain DataProtectorUsbCrypt.sys.");
            }

            return new UsbRuntimePackage
            {
                toolPath = toolPath,
                driverDirectory = Path.GetDirectoryName(driverFile),
                version = request.driverPackageVersion,
                sha256 = actualSha256
            };
        }

        private static Uri BuildPackageUri(Uri serverBaseUri, string downloadPath)
        {
            if (string.IsNullOrWhiteSpace(downloadPath))
            {
                throw new InvalidOperationException("USB crypt runtime package download path is missing.");
            }

            Uri absolute;
            if (Uri.TryCreate(downloadPath, UriKind.Absolute, out absolute))
            {
                return absolute;
            }

            return new Uri(serverBaseUri, downloadPath.TrimStart('/'));
        }

        private void PreparePublicToolArea(string targetRoot, UsbRuntimePackage runtimePackage)
        {
            string targetTool = Path.Combine(targetRoot, ToolFileName);
            string runtimeDirectory = Path.Combine(targetRoot, RuntimeDirectoryName);
            string targetDriverDirectory = Path.Combine(runtimeDirectory, "driver");

            DeleteRuntimeDirectory(runtimeDirectory, targetRoot);
            File.Copy(runtimePackage.toolPath, targetTool, true);
            CopyDirectory(runtimePackage.driverDirectory, targetDriverDirectory);
            File.WriteAllText(
                Path.Combine(runtimeDirectory, "runtime.json"),
                "{\"version\":\"" + EscapeJson(runtimePackage.version) + "\",\"sha256\":\"" + EscapeJson(runtimePackage.sha256) + "\"}",
                Encoding.UTF8);

            SetHiddenSystem(runtimeDirectory);
            SetHiddenSystemRecursively(runtimeDirectory);
        }

        private static void CopyDirectory(string source, string destination)
        {
            Directory.CreateDirectory(destination);
            foreach (string directory in Directory.GetDirectories(source, "*", SearchOption.AllDirectories))
            {
                Directory.CreateDirectory(Path.Combine(destination, directory.Substring(source.Length).TrimStart('\\', '/')));
            }

            foreach (string file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
            {
                string relative = file.Substring(source.Length).TrimStart('\\', '/');
                File.Copy(file, Path.Combine(destination, relative), true);
            }
        }

        private static void DeleteRuntimeDirectory(string runtimeDirectory, string targetRoot)
        {
            string root = Path.GetFullPath(targetRoot);
            string fullRuntime = Path.GetFullPath(runtimeDirectory);
            if (!fullRuntime.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Refusing to remove a runtime directory outside the USB public area.");
            }

            if (!Directory.Exists(fullRuntime))
            {
                return;
            }

            ClearAttributesRecursively(fullRuntime);
            Directory.Delete(fullRuntime, true);
        }

        private static void ClearAttributesRecursively(string directory)
        {
            foreach (string file in Directory.GetFiles(directory, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(file, FileAttributes.Normal);
            }

            foreach (string childDirectory in Directory.GetDirectories(directory, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(childDirectory, FileAttributes.Directory);
            }

            File.SetAttributes(directory, FileAttributes.Directory);
        }

        private static void SetHiddenSystemRecursively(string directory)
        {
            foreach (string file in Directory.GetFiles(directory, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(file, File.GetAttributes(file) | FileAttributes.Hidden | FileAttributes.System);
            }

            foreach (string childDirectory in Directory.GetDirectories(directory, "*", SearchOption.AllDirectories))
            {
                SetHiddenSystem(childDirectory);
            }
        }

        private static void SetHiddenSystem(string path)
        {
            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Hidden | FileAttributes.System);
        }

        private static byte[] BuildRawMetadata(
            UsbCryptInitializationRequest request,
            CentralPolicyStore.RemovableDeviceObservation target,
            byte[] key,
            long dataLengthBytes)
        {
            byte[] salt = new byte[PasswordSaltBytes];
            byte[] derived = new byte[KdfBytes];
            try
            {
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                byte[] passwordBytes = Utf16NoBom.GetBytes(request.password);
                using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(passwordBytes, salt, KdfIterations, HashAlgorithmName.SHA256))
                {
                    derived = kdf.GetBytes(KdfBytes);
                }

                byte[] buffer = new byte[MetadataBytes];
                using (MemoryStream stream = new MemoryStream(buffer))
                using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8))
                {
                    writer.Write(MetadataMagic);
                    writer.Write(MetadataVersion);
                    writer.Write((uint)MetadataBytes);
                    writer.Write(AlgorithmRc4);
                    writer.Write((uint)key.Length);
                    writer.Write((uint)KdfIterations);
                    writer.Write((ulong)request.publicToolAreaBytes);
                    writer.Write((ulong)request.publicToolAreaBytes);
                    writer.Write((ulong)dataLengthBytes);
                    writer.Write(salt);
                    writer.Write(derived.Take(PasswordVerifierBytes).ToArray());
                    writer.Write(WrapKey(key, derived));
                    WriteFixedUtf8(writer, target.hardwareId, MetadataDeviceIdBytes);
                    WriteFixedUtf8(writer, request.driverPackageVersion, MetadataVersionBytes);
                    WriteFixedUtf8(writer, request.driverPackageSha256, MetadataSha256Bytes);
                    writer.Write(new byte[MetadataReservedBytes]);
                    writer.Write(0u);
                }

                uint crc = Crc32(buffer, 0, MetadataBytes - sizeof(uint));
                Buffer.BlockCopy(BitConverter.GetBytes(crc), 0, buffer, MetadataBytes - sizeof(uint), sizeof(uint));
                return buffer;
            }
            finally
            {
                Array.Clear(salt, 0, salt.Length);
                Array.Clear(derived, 0, derived.Length);
            }
        }

        private static byte[] WrapKey(byte[] key, byte[] derived)
        {
            byte[] wrapped = new byte[ManifestKeyBytes];
            for (int index = 0; index < key.Length && index < wrapped.Length; index++)
            {
                wrapped[index] = (byte)(key[index] ^ derived[PasswordVerifierBytes + index]);
            }

            return wrapped;
        }

        private static void WriteFixedUtf8(BinaryWriter writer, string value, int byteCount)
        {
            byte[] buffer = new byte[byteCount];
            byte[] source = Encoding.UTF8.GetBytes(value ?? string.Empty);
            Buffer.BlockCopy(source, 0, buffer, 0, Math.Min(source.Length, buffer.Length - 1));
            writer.Write(buffer);
        }

        private static void WriteRawMetadata(string physicalDrivePath, byte[] metadata)
        {
            if (metadata == null || metadata.Length != MetadataBytes)
            {
                throw new InvalidOperationException("USB raw metadata block must be exactly 512 bytes.");
            }

            using (FileStream stream = new FileStream(physicalDrivePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                byte[] existing = new byte[MetadataBytes];
                stream.Seek(MetadataOffsetBytes, SeekOrigin.Begin);
                int read = stream.Read(existing, 0, existing.Length);
                if (read == existing.Length && !IsZeroBlock(existing) && !HasKnownMetadataMagic(existing))
                {
                    throw new InvalidOperationException("USB raw metadata sector is not empty and does not contain DataProtector metadata.");
                }

                stream.Seek(MetadataOffsetBytes, SeekOrigin.Begin);
                stream.Write(metadata, 0, metadata.Length);
                stream.Flush(true);
            }
        }

        private static bool IsZeroBlock(byte[] buffer)
        {
            return buffer.All(value => value == 0);
        }

        private static bool HasKnownMetadataMagic(byte[] buffer)
        {
            if (buffer == null || buffer.Length < sizeof(uint))
            {
                return false;
            }

            uint magic = BitConverter.ToUInt32(buffer, 0);
            return magic == MetadataMagic || magic == 0x31535544u;
        }

        private static PhysicalDiskTarget ResolvePhysicalDiskTarget(string driveRoot)
        {
            string logicalDeviceId = NormalizeDriveRoot(driveRoot).TrimEnd('\\');
            string escapedLogicalId = EscapeWmiString(logicalDeviceId);

            using (ManagementObjectSearcher partitionSearcher = new ManagementObjectSearcher(
                "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='" + escapedLogicalId + "'} WHERE AssocClass=Win32_LogicalDiskToPartition"))
            {
                foreach (ManagementObject partition in partitionSearcher.Get())
                {
                    using (partition)
                    {
                        string partitionDeviceId = Convert.ToString(partition["DeviceID"]);
                        if (string.IsNullOrWhiteSpace(partitionDeviceId))
                        {
                            continue;
                        }

                        long partitionOffset = Convert.ToInt64(partition["StartingOffset"] ?? 0);
                        using (ManagementObjectSearcher diskSearcher = new ManagementObjectSearcher(
                            "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + EscapeWmiString(partitionDeviceId) + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"))
                        {
                            foreach (ManagementObject disk in diskSearcher.Get())
                            {
                                using (disk)
                                {
                                    string physicalPath = Convert.ToString(disk["DeviceID"]);
                                    if (string.IsNullOrWhiteSpace(physicalPath))
                                    {
                                        continue;
                                    }

                                    return new PhysicalDiskTarget
                                    {
                                        physicalDrivePath = physicalPath,
                                        firstPartitionOffsetBytes = partitionOffset,
                                        diskSizeBytes = Convert.ToInt64(disk["Size"] ?? 0)
                                    };
                                }
                            }
                        }
                    }
                }
            }

            throw new InvalidOperationException("Unable to resolve the removable drive to a physical disk.");
        }

        private static void ValidateMetadataGap(PhysicalDiskTarget disk, long publicToolAreaBytes)
        {
            if (disk.diskSizeBytes <= MetadataOffsetBytes + MetadataBytes)
            {
                throw new InvalidOperationException("Target disk is too small for USB raw metadata.");
            }

            if (disk.firstPartitionOffsetBytes <= MetadataOffsetBytes + MetadataBytes)
            {
                throw new InvalidOperationException("Target disk partition starts before the reserved metadata sector; initialization was stopped to avoid corrupting the file system.");
            }

            if (publicToolAreaBytes < 5L * 1024L * 1024L)
            {
                throw new InvalidOperationException("Public tool area must be at least 5 MB.");
            }
        }

        private static void ExtractZipSafely(byte[] zipBytes, string destination)
        {
            using (MemoryStream memory = new MemoryStream(zipBytes))
            using (ZipArchive archive = new ZipArchive(memory, ZipArchiveMode.Read))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string relative = (entry.FullName ?? string.Empty).Replace('/', Path.DirectorySeparatorChar);
                    if (string.IsNullOrWhiteSpace(relative) || relative.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
                    {
                        continue;
                    }

                    if (Path.IsPathRooted(relative) || relative.Split(Path.DirectorySeparatorChar).Any(part => part == ".."))
                    {
                        throw new InvalidOperationException("USB crypt runtime package contains an unsafe path: " + entry.FullName);
                    }

                    string targetPath = Path.GetFullPath(Path.Combine(destination, relative));
                    string root = Path.GetFullPath(destination);
                    if (!targetPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("USB crypt runtime package contains an unsafe extraction target.");
                    }

                    Directory.CreateDirectory(Path.GetDirectoryName(targetPath));
                    entry.ExtractToFile(targetPath, true);
                }
            }
        }

        private static UsbCryptInitializationRequest NormalizeRequest(UsbCryptInitializationRequest request)
        {
            if (request == null)
            {
                throw new InvalidOperationException("USB initialization request is required.");
            }

            if (string.IsNullOrWhiteSpace(request.hardwareId))
            {
                throw new InvalidOperationException("USB hardware id is required.");
            }

            if (string.IsNullOrEmpty(request.password) || request.password.Length < 8)
            {
                throw new InvalidOperationException("Initialization password must contain at least 8 characters.");
            }

            if (string.IsNullOrWhiteSpace(request.driverPackageDownloadPath) ||
                string.IsNullOrWhiteSpace(request.driverPackageSha256))
            {
                throw new InvalidOperationException("USB crypt runtime package metadata is required.");
            }

            long toolArea = request.publicToolAreaBytes <= 0 ? 5L * 1024L * 1024L : request.publicToolAreaBytes;
            if (toolArea < 5L * 1024L * 1024L)
            {
                toolArea = 5L * 1024L * 1024L;
            }

            return new UsbCryptInitializationRequest
            {
                hardwareId = request.hardwareId.Trim(),
                password = request.password,
                publicToolAreaBytes = toolArea,
                dataLengthBytes = Math.Max(0, request.dataLengthBytes),
                confirmed = request.confirmed,
                driverPackageVersion = string.IsNullOrWhiteSpace(request.driverPackageVersion) ? "unversioned" : request.driverPackageVersion.Trim(),
                driverPackageSha256 = request.driverPackageSha256.Trim().ToLowerInvariant(),
                driverPackageDownloadPath = request.driverPackageDownloadPath.Trim()
            };
        }

        private static string NormalizeDriveRoot(string driveLetter)
        {
            if (string.IsNullOrWhiteSpace(driveLetter))
            {
                return string.Empty;
            }

            string value = driveLetter.Trim();
            if (value.Length == 2 && value[1] == ':')
            {
                return value + "\\";
            }

            return value.EndsWith("\\", StringComparison.Ordinal) ? value : value + "\\";
        }

        private static string ComputeSha256Hex(byte[] bytes)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return BitConverter.ToString(sha256.ComputeHash(bytes)).Replace("-", string.Empty).ToLowerInvariant();
            }
        }

        private static uint Crc32(byte[] bytes, int offset, int count)
        {
            uint crc = 0xFFFFFFFFu;
            for (int index = offset; index < offset + count; index++)
            {
                crc ^= bytes[index];
                for (int bit = 0; bit < 8; bit++)
                {
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
                }
            }

            return ~crc;
        }

        private static string EscapeWmiString(string value)
        {
            return (value ?? string.Empty).Replace("\\", "\\\\").Replace("'", "\\'");
        }

        private static string EscapeJson(string value)
        {
            return (value ?? string.Empty).Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        private static void DeleteDirectorySafe(string path)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
                {
                    Directory.Delete(path, true);
                }
            }
            catch
            {
            }
        }

        private sealed class UsbRuntimePackage
        {
            public string toolPath { get; set; }
            public string driverDirectory { get; set; }
            public string version { get; set; }
            public string sha256 { get; set; }
        }

        private sealed class PhysicalDiskTarget
        {
            public string physicalDrivePath { get; set; }
            public long firstPartitionOffsetBytes { get; set; }
            public long diskSizeBytes { get; set; }
        }

        public sealed class UsbCryptInitializationRequest
        {
            public string hardwareId { get; set; }
            public string password { get; set; }
            public long publicToolAreaBytes { get; set; }
            public long dataLengthBytes { get; set; }
            public bool confirmed { get; set; }
            public string driverPackageVersion { get; set; }
            public string driverPackageSha256 { get; set; }
            public string driverPackageDownloadPath { get; set; }
        }

        public sealed class UsbCryptInitializationResult
        {
            public string hardwareId { get; set; }
            public string driveLetter { get; set; }
            public string volumeGuid { get; set; }
            public long publicToolAreaBytes { get; set; }
            public long dataOffsetBytes { get; set; }
            public long dataLengthBytes { get; set; }
            public long metadataOffsetBytes { get; set; }
            public string metadataLocation { get; set; }
            public string toolPath { get; set; }
            public string driverPath { get; set; }
            public string driverPackageVersion { get; set; }
            public string driverPackageSha256 { get; set; }
            public bool dryRun { get; set; }
            public bool initialized { get; set; }
            public string message { get; set; }
        }
    }
}
