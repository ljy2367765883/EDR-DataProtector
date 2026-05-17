using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using DataProtectorWebBridge.Native;

namespace DataProtectorWebBridge.Services
{
    internal sealed class UsbCryptInitializer
    {
        private const int MetadataBytes = 512;
        private const long MetadataReservedBytes = 2L * 1024L * 1024L;
        private const long MetadataOffsetBytes = 1L * 1024L * 1024L;
        private const long PublicToolAreaBytes = 5L * 1024L * 1024L;
        private const long DataOffsetBytes = MetadataReservedBytes + PublicToolAreaBytes;
        private const int MetadataDeviceIdBytes = 128;
        private const int MetadataVersionBytes = 64;
        private const int MetadataSha256Bytes = 64;
        private const int MetadataReservedFieldBytes = 92;
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

            if (!normalized.confirmed)
            {
                ValidateUsbCryptInitializationPlan(disk, normalized.publicToolAreaBytes, normalized.hardwareId);
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
                targetRoot = ReinitializeDiskLayout(disk, normalized.publicToolAreaBytes, targetRoot, normalized.hardwareId);
                disk = ResolvePhysicalDiskTarget(targetRoot);
                ValidateUsbCryptLayout(disk, normalized.publicToolAreaBytes, normalized.hardwareId);
                PreparePublicToolArea(targetRoot, runtimePackage);

                long dataLength = normalized.dataLengthBytes > 0
                    ? normalized.dataLengthBytes
                    : Math.Max(0, disk.diskSizeBytes - DataOffsetBytes);

                byte[] metadata = BuildRawMetadata(normalized, target, key, dataLength);
                DataProtectorPolicyNative.NativeUsbMetadataWriteResult writeResult = WriteRawMetadataThroughDriver(disk.physicalDrivePath, metadata);

                return new UsbCryptInitializationResult
                {
                    hardwareId = target.hardwareId,
                    driveLetter = target.driveLetter,
                    volumeGuid = target.volumeGuid,
                    publicToolAreaBytes = normalized.publicToolAreaBytes,
                    dataOffsetBytes = DataOffsetBytes,
                    dataLengthBytes = dataLength,
                    metadataOffsetBytes = (long)writeResult.OffsetBytes,
                    metadataLocation = disk.physicalDrivePath + "@" + writeResult.OffsetBytes,
                    toolPath = Path.Combine(targetRoot, ToolFileName),
                    driverPath = Path.Combine(targetRoot, RuntimeDirectoryName),
                    driverPackageVersion = normalized.driverPackageVersion,
                    driverPackageSha256 = normalized.driverPackageSha256,
                    dryRun = false,
                    initialized = true,
                    message = "USB runtime package was copied and hidden; unlock metadata was written by the DataProtector driver into the reserved raw-disk metadata area."
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
                : Math.Max(0, disk.diskSizeBytes - DataOffsetBytes);

            return new UsbCryptInitializationResult
            {
                hardwareId = target.hardwareId,
                driveLetter = target.driveLetter,
                volumeGuid = target.volumeGuid,
                publicToolAreaBytes = request.publicToolAreaBytes,
                dataOffsetBytes = DataOffsetBytes,
                dataLengthBytes = dataLength,
                metadataOffsetBytes = MetadataOffsetBytes,
                metadataLocation = disk.physicalDrivePath + "@" + MetadataOffsetBytes,
                toolPath = Path.Combine(targetRoot, ToolFileName),
                driverPath = Path.Combine(targetRoot, RuntimeDirectoryName),
                driverPackageVersion = request.driverPackageVersion,
                driverPackageSha256 = request.driverPackageSha256,
                dryRun = true,
                initialized = false,
                message = "USB initialization dry run succeeded. Confirmed initialization will clean and repartition the USB disk as: 0-2 MB raw metadata reserve, 2-7 MB public tool partition, and 7 MB+ encrypted data region."
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
                    writer.Write((ulong)DataOffsetBytes);
                    writer.Write((ulong)dataLengthBytes);
                    writer.Write(salt);
                    writer.Write(derived.Take(PasswordVerifierBytes).ToArray());
                    writer.Write(WrapKey(key, derived));
                    WriteFixedUtf8(writer, target.hardwareId, MetadataDeviceIdBytes);
                    WriteFixedUtf8(writer, request.driverPackageVersion, MetadataVersionBytes);
                    WriteFixedUtf8(writer, request.driverPackageSha256, MetadataSha256Bytes);
                    writer.Write(new byte[MetadataReservedFieldBytes]);
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

        private static DataProtectorPolicyNative.NativeUsbMetadataWriteResult WriteRawMetadataThroughDriver(string physicalDrivePath, byte[] metadata)
        {
            if (metadata == null || metadata.Length != MetadataBytes)
            {
                throw new InvalidOperationException("USB raw metadata block must be exactly 512 bytes.");
            }

            DataProtectorPolicyNative.NativeUsbMetadataWriteResult result;
            uint status = DataProtectorPolicyNative.DpPolicyWriteUsbMetadata(
                physicalDrivePath,
                (ulong)MetadataOffsetBytes,
                metadata,
                out result);
            if (status != 0 || result.Status != 0)
            {
                throw new InvalidOperationException("DataProtector driver rejected USB raw metadata write: " + FormatNativeError(status != 0 ? status : result.Status));
            }

            return result;
        }

        private static string FormatNativeError(uint status)
        {
            StringBuilder message = new StringBuilder(512);
            try
            {
                DataProtectorPolicyNative.DpPolicyGetLastErrorMessage(message, (uint)message.Capacity);
            }
            catch
            {
            }

            string text = message.ToString();
            return "0x" + status.ToString("X8") + (string.IsNullOrWhiteSpace(text) ? string.Empty : " (" + text + ")");
        }

        private static string ReinitializeDiskLayout(PhysicalDiskTarget disk, long publicToolAreaBytes, string currentDriveRoot, string expectedHardwareId)
        {
            if (disk == null || string.IsNullOrWhiteSpace(disk.physicalDrivePath))
            {
                throw new InvalidOperationException("Physical USB disk is not available for layout initialization.");
            }

            int diskNumber = ParsePhysicalDriveNumber(disk.physicalDrivePath);
            ValidateUsbCryptInitializationPlan(disk, publicToolAreaBytes, expectedHardwareId);
            string volumeLabel = "DPUSB";
            Exception lastError = null;

            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    ValidatePhysicalDiskStillMatches(diskNumber, publicToolAreaBytes, expectedHardwareId);
                    BestEffortDismountPublicVolume(currentDriveRoot);
                    RunDiskPartScript(
                        diskNumber,
                        "prepare",
                        new[]
                        {
                            "rescan",
                            "select disk " + diskNumber,
                            "online disk noerr",
                            "attributes disk clear readonly noerr",
                            "clean"
                        });

                    WaitForPhysicalDisk(diskNumber, "after clean");
                    ValidatePhysicalDiskStillMatches(diskNumber, publicToolAreaBytes, expectedHardwareId);
                    RunDiskPartScript(
                        diskNumber,
                        "create-public-tool-partition",
                        new[]
                        {
                            "rescan",
                            "select disk " + diskNumber,
                            "online disk noerr",
                            "attributes disk clear readonly noerr",
                            "convert mbr",
                            "create partition primary size=5 offset=2048",
                            "format fs=ntfs quick unit=512 label=" + volumeLabel,
                            "assign",
                            "rescan"
                        });

                    Thread.Sleep(1500);
                    return WaitForToolPartition(diskNumber);
                }
                catch (Exception ex)
                {
                    lastError = ex;
                    RunDiskPartRescanBestEffort();
                    Thread.Sleep(1500 * attempt);
                }
            }

            throw new InvalidOperationException("Secure USB disk layout initialization failed after 3 attempts. Last error: " + (lastError == null ? "unknown" : lastError.Message), lastError);
        }

        private static int ParsePhysicalDriveNumber(string physicalDrivePath)
        {
            string value = (physicalDrivePath ?? string.Empty).Trim();
            int index = value.LastIndexOf("PhysicalDrive", StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                throw new InvalidOperationException("Physical drive path is invalid: " + physicalDrivePath);
            }

            string numberText = value.Substring(index + "PhysicalDrive".Length);
            int number;
            if (!int.TryParse(numberText, out number) || number < 0)
            {
                throw new InvalidOperationException("Physical drive number is invalid: " + physicalDrivePath);
            }

            return number;
        }

        private static string RunProcessChecked(string fileName, string arguments, string failureMessage)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using (Process process = Process.Start(startInfo))
            {
                if (process == null)
                {
                    throw new InvalidOperationException(failureMessage + " Process was not started.");
                }

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                if (!process.WaitForExit(120000))
                {
                    try
                    {
                        process.Kill();
                    }
                    catch
                    {
                    }

                    throw new InvalidOperationException(failureMessage + " diskpart timed out.");
                }

                if (process.ExitCode != 0)
                {
                    throw new InvalidOperationException(failureMessage + " ExitCode=" + process.ExitCode + " " + output + " " + error);
                }

                return output + error;
            }
        }

        private static void RunDiskPartScript(int diskNumber, string stage, string[] commands)
        {
            string scriptPath = Path.Combine(Path.GetTempPath(), "DataProtectorUsbDiskpart-" + stage + "-" + Guid.NewGuid().ToString("N") + ".txt");
            string script = string.Join(Environment.NewLine, commands) + Environment.NewLine + "exit" + Environment.NewLine;
            try
            {
                File.WriteAllText(scriptPath, script, Encoding.ASCII);
                RunProcessChecked(
                    "diskpart.exe",
                    "/s \"" + scriptPath + "\"",
                    "Secure USB disk layout initialization failed at stage '" + stage + "' for disk " + diskNumber + ". Script: " + script.Replace(Environment.NewLine, " | "));
            }
            finally
            {
                try
                {
                    if (File.Exists(scriptPath))
                    {
                        File.Delete(scriptPath);
                    }
                }
                catch
                {
                }
            }
        }

        private static void RunDiskPartRescanBestEffort()
        {
            string scriptPath = Path.Combine(Path.GetTempPath(), "DataProtectorUsbDiskpart-rescan-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(scriptPath, "rescan" + Environment.NewLine + "exit" + Environment.NewLine, Encoding.ASCII);
                RunProcessChecked("diskpart.exe", "/s \"" + scriptPath + "\"", "DiskPart rescan failed.");
            }
            catch
            {
            }
            finally
            {
                try
                {
                    if (File.Exists(scriptPath))
                    {
                        File.Delete(scriptPath);
                    }
                }
                catch
                {
                }
            }
        }

        private static void BestEffortDismountPublicVolume(string currentDriveRoot)
        {
            string root = NormalizeDriveRoot(currentDriveRoot);
            if (string.IsNullOrWhiteSpace(root) || root.Length < 3 || root[1] != ':')
            {
                return;
            }

            try
            {
                RunProcessChecked("mountvol.exe", "\"" + root + "\" /p", "Secure USB public volume dismount failed.");
            }
            catch
            {
            }

            Thread.Sleep(500);
        }

        private static void WaitForPhysicalDisk(int diskNumber, string stage)
        {
            DateTime deadline = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < deadline)
            {
                if (PhysicalDiskExists(diskNumber))
                {
                    return;
                }

                Thread.Sleep(500);
            }

            throw new InvalidOperationException("Physical disk " + diskNumber + " did not become available " + stage + ".");
        }

        private static bool PhysicalDiskExists(int diskNumber)
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                "SELECT DeviceID FROM Win32_DiskDrive WHERE Index=" + diskNumber))
            {
                foreach (ManagementObject disk in searcher.Get())
                {
                    using (disk)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static void ValidatePhysicalDiskStillMatches(int diskNumber, long publicToolAreaBytes, string expectedHardwareId)
        {
            PhysicalDiskTarget current = ResolvePhysicalDiskTargetByNumber(diskNumber);
            ValidateUsbCryptInitializationPlan(current, publicToolAreaBytes, expectedHardwareId);
        }

        private static PhysicalDiskTarget ResolvePhysicalDiskTargetByNumber(int diskNumber)
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_DiskDrive WHERE Index=" + diskNumber))
            {
                foreach (ManagementObject disk in searcher.Get())
                {
                    using (disk)
                    {
                        return PhysicalDiskTargetFromDisk(disk, 0);
                    }
                }
            }

            throw new InvalidOperationException("Physical disk " + diskNumber + " is not available.");
        }

        private static string WaitForToolPartition(int diskNumber)
        {
            DateTime deadline = DateTime.UtcNow.AddSeconds(30);
            while (DateTime.UtcNow < deadline)
            {
                string root = TryFindToolPartitionRoot(diskNumber);
                if (!string.IsNullOrWhiteSpace(root))
                {
                    return root;
                }

                Thread.Sleep(1000);
            }

            throw new InvalidOperationException("Secure USB public tool partition was created, but no drive letter became available.");
        }

        private static string TryFindToolPartitionRoot(int diskNumber)
        {
            using (ManagementObjectSearcher partitionSearcher = new ManagementObjectSearcher(
                "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='\\\\\\\\.\\\\PHYSICALDRIVE" + diskNumber + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"))
            {
                foreach (ManagementObject partition in partitionSearcher.Get())
                {
                    using (partition)
                    {
                        long offset = Convert.ToInt64(partition["StartingOffset"] ?? 0);
                        if (offset != MetadataReservedBytes)
                        {
                            continue;
                        }

                        string partitionDeviceId = Convert.ToString(partition["DeviceID"]);
                        using (ManagementObjectSearcher logicalSearcher = new ManagementObjectSearcher(
                            "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + EscapeWmiString(partitionDeviceId) + "'} WHERE AssocClass=Win32_LogicalDiskToPartition"))
                        {
                            foreach (ManagementObject logical in logicalSearcher.Get())
                            {
                                using (logical)
                                {
                                    string deviceId = Convert.ToString(logical["DeviceID"]);
                                    if (!string.IsNullOrWhiteSpace(deviceId))
                                    {
                                        return NormalizeDriveRoot(deviceId);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            return string.Empty;
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

                                    return PhysicalDiskTargetFromDisk(disk, partitionOffset);
                                }
                            }
                        }
                    }
                }
            }

            throw new InvalidOperationException("Unable to resolve the removable drive to a physical disk.");
        }

        private static PhysicalDiskTarget PhysicalDiskTargetFromDisk(ManagementBaseObject disk, long firstPartitionOffsetBytes)
        {
            return new PhysicalDiskTarget
            {
                physicalDrivePath = Convert.ToString(disk["DeviceID"]),
                firstPartitionOffsetBytes = firstPartitionOffsetBytes,
                diskSizeBytes = Convert.ToInt64(disk["Size"] ?? 0),
                model = Convert.ToString(disk["Model"]),
                serialNumber = Convert.ToString(disk["SerialNumber"]),
                pnpDeviceId = Convert.ToString(disk["PNPDeviceID"]),
                interfaceType = Convert.ToString(disk["InterfaceType"]),
                mediaType = Convert.ToString(disk["MediaType"])
            };
        }

        private static void ValidateUsbCryptLayout(PhysicalDiskTarget disk, long publicToolAreaBytes, string expectedHardwareId)
        {
            ValidateUsbCryptInitializationPlan(disk, publicToolAreaBytes, expectedHardwareId);

            if (disk.diskSizeBytes <= DataOffsetBytes + MetadataBytes)
            {
                throw new InvalidOperationException("Target disk is too small for the Secure USB layout.");
            }

            if (disk.firstPartitionOffsetBytes < MetadataReservedBytes)
            {
                throw new InvalidOperationException("Target disk partition starts before the 2 MB reserved metadata area. Reinitialize the USB disk layout before enabling Secure USB.");
            }

            if (disk.firstPartitionOffsetBytes != MetadataReservedBytes)
            {
                throw new InvalidOperationException("Secure USB requires the public tool partition to start exactly at 2 MB. Reinitialize the USB disk layout from the Agent before copying runtime files.");
            }

            if (publicToolAreaBytes != PublicToolAreaBytes)
            {
                throw new InvalidOperationException("Secure USB public tool area must be exactly 5 MB.");
            }
        }

        private static void ValidateUsbCryptInitializationPlan(PhysicalDiskTarget disk, long publicToolAreaBytes, string expectedHardwareId)
        {
            if (disk == null || string.IsNullOrWhiteSpace(disk.physicalDrivePath))
            {
                throw new InvalidOperationException("Physical USB disk is not available for Secure USB initialization.");
            }

            if (disk.diskSizeBytes <= DataOffsetBytes + MetadataBytes)
            {
                throw new InvalidOperationException("Target disk is too small for the Secure USB layout.");
            }

            if (!disk.IsUsbOrRemovable)
            {
                throw new InvalidOperationException("Refusing Secure USB initialization because the target physical disk is not reported as USB/removable.");
            }

            string actualHardwareId = RemovableDeviceInventory.ComputeHardwareIdFromDiskIdentity(
                disk.pnpDeviceId,
                disk.serialNumber,
                disk.model,
                disk.interfaceType,
                disk.mediaType);
            if (string.IsNullOrWhiteSpace(actualHardwareId) ||
                !string.Equals(actualHardwareId, expectedHardwareId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Refusing Secure USB initialization because the physical disk identity no longer matches the selected removable device.");
            }

            if (publicToolAreaBytes != PublicToolAreaBytes)
            {
                throw new InvalidOperationException("Secure USB public tool area must be exactly 5 MB.");
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

            long toolArea = request.publicToolAreaBytes <= 0 ? PublicToolAreaBytes : request.publicToolAreaBytes;
            if (toolArea != PublicToolAreaBytes)
            {
                throw new InvalidOperationException("Secure USB public tool area must be exactly 5 MB.");
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
            public string model { get; set; }
            public string serialNumber { get; set; }
            public string pnpDeviceId { get; set; }
            public string interfaceType { get; set; }
            public string mediaType { get; set; }

            public bool IsUsbOrRemovable
            {
                get
                {
                    string normalizedInterface = (interfaceType ?? string.Empty).Trim();
                    string normalizedPnp = (pnpDeviceId ?? string.Empty).Trim();
                    string normalizedMedia = (mediaType ?? string.Empty).Trim();
                    return string.Equals(normalizedInterface, "USB", StringComparison.OrdinalIgnoreCase) ||
                           normalizedPnp.StartsWith("USB", StringComparison.OrdinalIgnoreCase) ||
                           normalizedPnp.IndexOf("USBSTOR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                           normalizedMedia.IndexOf("removable", StringComparison.OrdinalIgnoreCase) >= 0 ||
                           normalizedMedia.IndexOf("flash", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
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
