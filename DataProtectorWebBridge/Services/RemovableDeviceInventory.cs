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

            try
            {
                foreach (DriveInfo drive in DriveInfo.GetDrives())
                {
                    if (drive.DriveType != DriveType.Removable)
                    {
                        continue;
                    }

                    CentralPolicyStore.RemovableDeviceObservation observation = BuildObservation(drive);
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

            return devices
                .GroupBy(item => item.hardwareId, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .ToArray();
        }

        private static CentralPolicyStore.RemovableDeviceObservation BuildObservation(DriveInfo drive)
        {
            string driveName = NormalizeDriveName(drive.Name);
            DiskMetadata metadata = QueryDiskMetadata(driveName);
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

            string rawIdentity = string.Join("|", new[]
            {
                metadata.PnpDeviceId,
                metadata.SerialNumber,
                metadata.Model,
                metadata.InterfaceType,
                metadata.MediaType,
                totalSize.ToString()
            });

            string fallbackIdentity = string.Join("|", new[]
            {
                driveName,
                volumeGuid,
                volumeLabel,
                fileSystem,
                totalSize.ToString()
            });

            string hardwareId = ComputeHardwareId(string.IsNullOrWhiteSpace(rawIdentity.Replace("|", string.Empty)) ? fallbackIdentity : rawIdentity);
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

        private static string QueryVolumeGuid(string driveName)
        {
            try
            {
                string root = driveName.EndsWith("\\", StringComparison.Ordinal) ? driveName : driveName + "\\";
                StringBuilder buffer = new StringBuilder(128);
                if (GetVolumeNameForVolumeMountPoint(root, buffer, buffer.Capacity))
                {
                    return buffer.ToString().TrimEnd('\\');
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
                                        metadata.Model = Clean(Convert.ToString(disk["Model"]));
                                        metadata.SerialNumber = Clean(Convert.ToString(disk["SerialNumber"]));
                                        metadata.PnpDeviceId = Clean(Convert.ToString(disk["PNPDeviceID"]));
                                        metadata.InterfaceType = Clean(Convert.ToString(disk["InterfaceType"]));
                                        metadata.MediaType = Clean(Convert.ToString(disk["MediaType"]));
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

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVolumeNameForVolumeMountPoint(string volumeMountPoint, StringBuilder volumeName, int bufferLength);
    }
}
