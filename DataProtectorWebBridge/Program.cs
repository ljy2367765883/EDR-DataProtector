using System;
using System.Net;
using DataProtectorWebBridge.Services;

namespace DataProtectorWebBridge
{
    internal static class Program
    {
        private const string DefaultPrefix = "http://+:17643/";

        private static int Main(string[] args)
        {
            string prefix = args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0])
                ? NormalizeHttpSysPrefix(args[0])
                : DefaultPrefix;
            string webRoot = args != null && args.Length > 1 && !string.IsNullOrWhiteSpace(args[1])
                ? args[1]
                : "web";

            try
            {
                AuditLog auditLog = new AuditLog();
                PolicyBridgeService policyService = new PolicyBridgeService(auditLog);

                using (HttpBridgeServer server = new HttpBridgeServer(prefix, policyService, auditLog, webRoot))
                {
                    server.Start();
                }

                return 0;
            }
            catch (HttpListenerException ex)
            {
                Console.Error.WriteLine("Cannot start DataProtector Web Bridge: " + ex.Message);
                Console.Error.WriteLine("For non-admin execution, reserve the URL with:");
                Console.Error.WriteLine("netsh http add urlacl url=" + prefix + " user=%USERNAME%");
                Console.Error.WriteLine("For remote access, allow TCP 17643 through Windows Firewall.");
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                return 1;
            }
        }

        private static string NormalizeHttpSysPrefix(string prefix)
        {
            string value = prefix == null ? string.Empty : prefix.Trim();
            if (value.StartsWith("http://0.0.0.0:", StringComparison.OrdinalIgnoreCase))
            {
                return "http://+:" + value.Substring("http://0.0.0.0:".Length);
            }

            return value;
        }
    }
}
