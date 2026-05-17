using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace DataProtectorWebBridge.Services
{
    internal sealed class RemovableDeviceInventory
    {
        public CentralPolicyStore.RemovableDeviceObservation[] Snapshot()
        {
            List<CentralPolicyStore.RemovableDeviceObservation> devices = new List<CentralPolicyStore.RemovableDeviceObservation>();
            HashSet<string> seenDrives = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                foreach (UsbLogicalDisk logicalDisk in QueryUsbLogicalDisks())
                {
                    string driveName = NormalizeDriveName(logicalDisk.DriveName);
                    if (string.IsNullOrWhiteSpace(driveName) || !seenDrives.Add(driveName))
                    {
                        continue;
                    }

                    CentralPolicyStore.RemovableDeviceObservation observation = BuildObservation(driveName, logicalDisk.Metadata);
                    if (observation != null)
                    {
                        devices.Add(observation);
                    }
                }

                foreach (DriveInfo drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType != DriveType.Removable)
                    {
                        continue;
                    }

                    string driveName = NormalizeDriveName(drive.Name);
                    if (string.IsNullOrWhiteSpace(driveName) || !seenDrives.Add(driveName))
                    {
                        continue;
                    }

                    CentralPolicyStore.RemovableDeviceObservation observation = BuildObservation(drive, null);
                    if (observation != null)
                    {
                        devices.Add(observation);
                    }
                }
            }
            catch
            {
                return devices.ToArray();
            }

            return devices.ToArray();
        }

        private static CentralPolicyStore.RemovableDeviceObservation BuildObservation(string driveName, DiskMetadata metadata)
        {
            try
            {
                string root = driveName.EndsWith("\\", StringComparison.Ordinal) ? driveName : driveName + "\\";
                return BuildObservation(new DriveInfo(root), metadata);
            }
            catch
            {
                return null;
            }
        }

        private static CentralPolicyStore.RemovableDeviceObservation BuildObservation(DriveInfo drive)
        {
            return BuildObservation(drive, null);
        }

        private static CentralPolicyStore.RemovableDeviceObservation BuildObservation(DriveInfo drive, DiskMetadata metadataOverride)
        {
            string driveName = NormalizeDriveName(drive.Name);
            DiskMetadata metadata = metadataOverride ?? QueryDiskMetadata(driveName);
            string volumeGuid = QueryVolumeGuid(driveName);
            string volumeLabel = string.Empty;
            string fileSystem = string.Empty;
            long totalSize = 0;

            try
            {
                if (drive.IsReady)
                {
                    volumeLabel = drive.VolumeLabel ?? string.Empty;
                    fileSystem = drive.DriveFormat ?? string.Empty;
                    totalSize = drive.TotalSize;
                }
            }
            catch
            {
                volumeLabel = string.Empty;
                fileSystem = string.Empty;
                totalSize = 0;
            }

            string hardwareId = ComputeHardwareId(BuildPhysicalIdentity(metadata));
            if (string.IsNullOrWhiteSpace(hardwareId))
            {
                return null;
            }

            return new CentralPolicyStore.RemovableDeviceObservation
            {
                hardwareId = hardwareId,
                driveLetter = driveName,
                volumeGuid = volumeGuid,
                volumeLabel = volumeLabel,
                fileSystem = fileSystem,
                sizeBytes = totalSize,
                model = metadata.Model,
                serialNumber = metadata.SerialNumber,
                pnpDeviceId = metadata.PnpDeviceId,
                interfaceType = metadata.InterfaceType,
                mediaType = metadata.MediaType,
                lastSeenUtc = DateTime.UtcNow.ToString("o")
            };
        }

        private static IEnumerable<UsbLogicalDisk> QueryUsbLogicalDisks()
        {
            List<UsbLogicalDisk> disks = new List<UsbLogicalDisk>();

            try
            {
                using (ManagementObjectSearcher diskSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject disk in diskSearcher.Get())
                    {
                        using (disk)
                        {
                            if (!IsUsbOrRemovableDisk(disk))
                            {
                                continue;
                            }

                            string diskDeviceId = Convert.ToString(disk["DeviceID"]);
                            if (string.IsNullOrWhiteSpace(diskDeviceId))
                            {
                                continue;
                            }

                            DiskMetadata metadata = DiskMetadataFromDisk(disk);
                            using (ManagementObjectSearcher partitionSearcher = new ManagementObjectSearcher(
                                "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + EscapeWmiString(diskDeviceId) + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"))
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

                                        using (ManagementObjectSearcher logicalSearcher = new ManagementObjectSearcher(
                                            "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + EscapeWmiString(partitionDeviceId) + "'} WHERE AssocClass=Win32_LogicalDiskToPartition"))
                                        {
                                            foreach (ManagementObject logicalDisk in logicalSearcher.Get())
                                            {
                                                using (logicalDisk)
                                                {
                                                    string driveName = Convert.ToString(logicalDisk["DeviceID"]);
                                                    if (!string.IsNullOrWhiteSpace(driveName))
                                                    {
                                                        disks.Add(new UsbLogicalDisk
                                                        {
                                                            DriveName = driveName,
                                                            Metadata = metadata
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                return disks;
            }

            return disks;
        }

        private static string QueryVolumeGuid(string driveName)
        {
            try
            {
                string root = driveName.EndsWith("\\", StringComparison.Ordinal) ? driveName : driveName + "\\";
                StringBuilder buffer = new StringBuilder(128);
                if (GetVolumeNameForVolumeMountPoint(root, buffer, buffer.Capacity))
                {
                    return NormalizeKernelVolumeName(buffer.ToString());
                }
            }
            catch
            {
                return string.Empty;
            }

            return string.Empty;
        }

        private static DiskMetadata QueryDiskMetadata(string driveName)
        {
            DiskMetadata metadata = new DiskMetadata();

            try
            {
                string logicalDeviceId = EscapeWmiString(driveName.TrimEnd('\\'));
                using (ManagementObjectSearcher partitionSearcher = new ManagementObjectSearcher(
                    "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='" + logicalDeviceId + "'} WHERE AssocClass=Win32_LogicalDiskToPartition"))
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

                            using (ManagementObjectSearcher diskSearcher = new ManagementObjectSearcher(
                                "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + EscapeWmiString(partitionDeviceId) + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"))
                            {
                                foreach (ManagementObject disk in diskSearcher.Get())
                                {
                                    using (disk)
                                    {
                                        metadata = DiskMetadataFromDisk(disk);
                                        return metadata;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                return metadata;
            }

            return metadata;
        }

        private static DiskMetadata DiskMetadataFromDisk(ManagementBaseObject disk)
        {
            if (disk == null)
            {
                return new DiskMetadata();
            }

            return new DiskMetadata
            {
                Model = Clean(Convert.ToString(disk["Model"])),
                SerialNumber = Clean(Convert.ToString(disk["SerialNumber"])),
                PnpDeviceId = Clean(Convert.ToString(disk["PNPDeviceID"])),
                InterfaceType = Clean(Convert.ToString(disk["InterfaceType"])),
                MediaType = Clean(Convert.ToString(disk["MediaType"]))
            };
        }

        private static bool IsUsbOrRemovableDisk(ManagementBaseObject disk)
        {
            string interfaceType = Clean(Convert.ToString(disk["InterfaceType"]));
            string pnpDeviceId = Clean(Convert.ToString(disk["PNPDeviceID"]));
            string mediaType = Clean(Convert.ToString(disk["MediaType"]));

            return string.Equals(interfaceType, "USB", StringComparison.OrdinalIgnoreCase) ||
                   pnpDeviceId.StartsWith("USB", StringComparison.OrdinalIgnoreCase) ||
                   pnpDeviceId.IndexOf("USBSTOR", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   mediaType.IndexOf("removable", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   mediaType.IndexOf("flash", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string ComputeHardwareId(string identity)
        {
            string normalized = Clean(identity).ToUpperInvariant();
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return string.Empty;
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(normalized);
                return BitConverter.ToString(sha256.ComputeHash(bytes)).Replace("-", string.Empty).ToLowerInvariant();
            }
        }

        private static string BuildPhysicalIdentity(DiskMetadata metadata)
        {
            if (metadata == null)
            {
                return string.Empty;
            }

            string pnpDeviceId = Clean(metadata.PnpDeviceId);
            if (!string.IsNullOrWhiteSpace(pnpDeviceId))
            {
                return "USB-PNP|" + pnpDeviceId;
            }

            string serialNumber = Clean(metadata.SerialNumber);
            string model = Clean(metadata.Model);
            if (!string.IsNullOrWhiteSpace(serialNumber))
            {
                return "DISK-SERIAL|" + serialNumber + "|" + model + "|" + Clean(metadata.InterfaceType);
            }

            if (!string.IsNullOrWhiteSpace(model) || !string.IsNullOrWhiteSpace(metadata.InterfaceType))
            {
                return "DISK-PHYSICAL|" + model + "|" + Clean(metadata.InterfaceType) + "|" + Clean(metadata.MediaType);
            }

            return string.Empty;
        }

        private static string NormalizeKernelVolumeName(string value)
        {
            string normalized = Clean(value).TrimEnd('\\');
            if (normalized.StartsWith("\\\\?\\", StringComparison.Ordinal))
            {
                normalized = "\\??\\" + normalized.Substring(4);
            }

            return normalized;
        }

        private static string NormalizeDriveName(string driveName)
        {
            if (string.IsNullOrWhiteSpace(driveName))
            {
                return string.Empty;
            }

            return driveName.TrimEnd('\\').ToUpperInvariant();
        }

        private static string Clean(string value)
        {
            return (value ?? string.Empty).Trim();
        }

        private static string EscapeWmiString(string value)
        {
            return (value ?? string.Empty).Replace("\\", "\\\\").Replace("'", "\\'");
        }

        private sealed class DiskMetadata
        {
            public string Model { get; set; }
            public string SerialNumber { get; set; }
            public string PnpDeviceId { get; set; }
            public string InterfaceType { get; set; }
            public string MediaType { get; set; }
        }

        private sealed class UsbLogicalDisk
        {
            public string DriveName { get; set; }
            public DiskMetadata Metadata { get; set; }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumeNameForVolumeMountPoint(string volumeMountPoint, StringBuilder volumeName, int bufferLength);
    }
}
