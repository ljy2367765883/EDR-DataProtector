using System;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using DataProtectorAdmin.Infrastructure;
using DataProtectorAdmin.Models;

namespace DataProtectorAdmin.Services
{
    public sealed class PolicySettingsStore : IPolicySettingsStore
    {
        private readonly string settingsPath;

        public PolicySettingsStore()
        {
            string directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "DataProtector");

            settingsPath = Path.Combine(directory, "policy-rules.xml");
        }

        public PolicySettings Load()
        {
            PolicySettings settings = new PolicySettings();

            if (!File.Exists(settingsPath))
            {
                SeedDefaults(settings);
                Save(settings);
                return settings;
            }

            try
            {
                XDocument document = XDocument.Load(settingsPath);
                XElement root = document.Root;

                if (root == null)
                {
                    return settings;
                }

                foreach (XElement element in root.Element("ProcessNameRules") != null
                    ? root.Element("ProcessNameRules").Elements("Rule")
                    : Enumerable.Empty<XElement>())
                {
                    string value = (string)element.Attribute("Value");
                    string extension = NormalizeExtension((string)element.Attribute("Extension"));
                    if (!string.IsNullOrWhiteSpace(value) &&
                        !settings.ProcessNameRules.Any(rule => RuleEquals(rule, value, extension)))
                    {
                        settings.ProcessNameRules.Add(new PolicyRule(PolicyRuleKind.ProcessName, value, value, extension));
                    }
                }

                foreach (XElement element in root.Element("ProcessDirectoryRules") != null
                    ? root.Element("ProcessDirectoryRules").Elements("Rule")
                    : Enumerable.Empty<XElement>())
                {
                    string displayValue = (string)element.Attribute("DisplayValue");
                    string driverValue = (string)element.Attribute("DriverValue");
                    string extension = NormalizeExtension((string)element.Attribute("Extension"));

                    if (!string.IsNullOrWhiteSpace(displayValue) &&
                        !string.IsNullOrWhiteSpace(driverValue) &&
                        !settings.ProcessDirectoryRules.Any(rule => RuleEquals(rule, driverValue, extension)))
                    {
                        settings.ProcessDirectoryRules.Add(new PolicyRule(PolicyRuleKind.ProcessDirectory, displayValue, driverValue, extension));
                    }
                }

                foreach (XElement element in root.Element("ExcludedDirectoryRules") != null
                    ? root.Element("ExcludedDirectoryRules").Elements("Rule")
                    : Enumerable.Empty<XElement>())
                {
                    string displayValue = (string)element.Attribute("DisplayValue");
                    string driverValue = (string)element.Attribute("DriverValue");
                    string extension = NormalizeExtension((string)element.Attribute("Extension"));

                    if (!string.IsNullOrWhiteSpace(displayValue) &&
                        !string.IsNullOrWhiteSpace(driverValue) &&
                        !settings.ExcludedDirectoryRules.Any(rule => RuleEquals(rule, driverValue, extension)))
                    {
                        settings.ExcludedDirectoryRules.Add(new PolicyRule(PolicyRuleKind.ExcludedDirectory, displayValue, driverValue, extension));
                    }
                }
            }
            catch
            {
                AdminDiagnostics.Log("Failed to load policy settings. Falling back to defaults.");
                SeedDefaults(settings);
            }

            return settings;
        }

        public void Save(PolicySettings settings)
        {
            string directory = Path.GetDirectoryName(settingsPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            XDocument document = new XDocument(
                new XElement("PolicySettings",
                    new XElement("ProcessNameRules",
                        settings.ProcessNameRules
                            .GroupBy(rule => BuildRuleKey(rule), StringComparer.OrdinalIgnoreCase)
                            .OrderBy(group => group.First().DriverValue, StringComparer.OrdinalIgnoreCase)
                            .Select(group => new XElement("Rule",
                                new XAttribute("Value", group.First().DriverValue),
                                new XAttribute("Extension", group.First().Extension)))),
                    new XElement("ProcessDirectoryRules",
                        settings.ProcessDirectoryRules
                            .GroupBy(rule => BuildRuleKey(rule), StringComparer.OrdinalIgnoreCase)
                            .OrderBy(group => group.First().DisplayValue, StringComparer.OrdinalIgnoreCase)
                            .Select(group => new XElement("Rule",
                                new XAttribute("DisplayValue", group.First().DisplayValue),
                                new XAttribute("DriverValue", group.First().DriverValue),
                                new XAttribute("Extension", group.First().Extension)))),
                    new XElement("ExcludedDirectoryRules",
                        settings.ExcludedDirectoryRules
                            .GroupBy(rule => BuildRuleKey(rule), StringComparer.OrdinalIgnoreCase)
                            .OrderBy(group => group.First().DisplayValue, StringComparer.OrdinalIgnoreCase)
                            .Select(group => new XElement("Rule",
                                new XAttribute("DisplayValue", group.First().DisplayValue),
                                new XAttribute("DriverValue", group.First().DriverValue),
                                new XAttribute("Extension", group.First().Extension))))));

            SaveAtomically(document);
        }

        private void SaveAtomically(XDocument document)
        {
            string tempPath = settingsPath + "." + Guid.NewGuid().ToString("N") + ".tmp";

            try
            {
                document.Save(tempPath);

                if (File.Exists(settingsPath))
                {
                    File.Replace(tempPath, settingsPath, null);
                }
                else
                {
                    File.Move(tempPath, settingsPath);
                }
            }
            finally
            {
                try
                {
                    if (File.Exists(tempPath))
                    {
                        File.Delete(tempPath);
                    }
                }
                catch
                {
                    AdminDiagnostics.Log("Failed to remove temporary policy settings file: " + tempPath);
                }
            }
        }

        private static void SeedDefaults(PolicySettings settings)
        {
            string[] defaults = { "cmd.exe", "powershell.exe", "notepad.exe" };

            foreach (string processName in defaults)
            {
                settings.ProcessNameRules.Add(new PolicyRule(PolicyRuleKind.ProcessName, processName, processName, ".dpf"));
            }
        }

        private static bool RuleEquals(PolicyRule rule, string driverValue, string extension)
        {
            return string.Equals(rule.DriverValue, driverValue, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(rule.Extension, extension, StringComparison.OrdinalIgnoreCase);
        }

        private static string BuildRuleKey(PolicyRule rule)
        {
            return rule.DriverValue + "|" + NormalizeExtension(rule.Extension);
        }

        private static string NormalizeExtension(string extension)
        {
            string normalized = string.IsNullOrWhiteSpace(extension) ? ".dpf" : extension.Trim();
            return normalized.StartsWith(".", StringComparison.Ordinal) ? normalized : "." + normalized;
        }
    }
}
