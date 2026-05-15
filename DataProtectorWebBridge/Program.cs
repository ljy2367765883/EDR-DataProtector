using System;
using System.Net;
using DataProtectorWebBridge.Services;

namespace DataProtectorWebBridge
{
    internal static class Program
    {
        private const string DefaultPrefix = "http://127.0.0.1:17643/";

        private static int Main(string[] args)
        {
            string prefix = args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0])
                ? args[0]
                : DefaultPrefix;

            try
            {
                AuditLog auditLog = new AuditLog();
                PolicyBridgeService policyService = new PolicyBridgeService(auditLog);

                using (HttpBridgeServer server = new HttpBridgeServer(prefix, policyService, auditLog))
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
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                return 1;
            }
        }
    }
}
