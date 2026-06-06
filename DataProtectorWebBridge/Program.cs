using System;
using System.Net;
using DataProtectorWebBridge.Services;

namespace DataProtectorWebBridge
{
    internal static class Program
    {
        private const string DefaultPrefix = "http://+:17643/";
        private const string DefaultWebRoot = "web";

        private static int Main(string[] args)
        {
            string mode = args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0])
                ? args[0].Trim().ToLowerInvariant()
                : "server";

            try
            {
                if (mode == "agent")
                {
                    return RunAgent(args);
                }

                if (mode == "standalone")
                {
                    return RunStandalone(args);
                }

                if (mode == "server")
                {
                    return RunServer(args);
                }

                PrintUsage();
                return 2;
            }
            catch (HttpListenerException ex)
            {
                Console.Error.WriteLine("Cannot start DataProtector Web Bridge: " + ex.Message);
                Console.Error.WriteLine("For non-admin execution, reserve the URL with:");
                Console.Error.WriteLine("netsh http add urlacl url=" + DefaultPrefix + " user=%USERNAME%");
                Console.Error.WriteLine("For remote access, allow TCP 17643 through Windows Firewall.");
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                return 1;
            }
        }

        private static int RunServer(string[] args)
        {
            string prefix = GetArg(args, 1, DefaultPrefix);
            string webRoot = GetArg(args, 2, DefaultWebRoot);

            using (CentralHttpServer server = new CentralHttpServer(NormalizeHttpSysPrefix(prefix), new CentralPolicyStore(), webRoot))
            {
                server.Start();
            }

            return 0;
        }

        private static int RunAgent(string[] args)
        {
            string serverUrl = GetArg(args, 1, string.Empty);
            if (string.IsNullOrWhiteSpace(serverUrl))
            {
                Console.Error.WriteLine("Agent mode requires a central server URL.");
                PrintUsage();
                return 2;
            }

            int seconds = 15;
            int.TryParse(GetArg(args, 2, "15"), out seconds);

            AuditLog auditLog = new AuditLog();
            PolicyBridgeService policyService = new PolicyBridgeService(auditLog);
            AgentSyncClient agent = new AgentSyncClient(serverUrl, TimeSpan.FromSeconds(Math.Max(1, seconds)), policyService);
            agent.Run();
            return 0;
        }

        private static int RunStandalone(string[] args)
        {
            string prefix = GetArg(args, 1, DefaultPrefix);
            string webRoot = GetArg(args, 2, DefaultWebRoot);
            AuditLog auditLog = new AuditLog();
            PolicyBridgeService policyService = new PolicyBridgeService(auditLog);

            TryPrepareUserHookRuntime(policyService);

            using (HttpBridgeServer server = new HttpBridgeServer(NormalizeHttpSysPrefix(prefix), policyService, auditLog, webRoot))
            {
                server.Start();
            }

            return 0;
        }

        private static void TryPrepareUserHookRuntime(PolicyBridgeService policyService)
        {
            try
            {
                string runtimePath = policyService.EnsureUserHookRuntimePrepared();
                Console.WriteLine(DateTime.Now.ToString("s") + " User hook runtime prepared: " + runtimePath);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(DateTime.Now.ToString("s") + " user hook runtime bootstrap failed: " + ex.Message);
            }
        }

        private static string GetArg(string[] args, int index, string fallback)
        {
            return args != null && args.Length > index && !string.IsNullOrWhiteSpace(args[index])
                ? args[index]
                : fallback;
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine("Usage:");
            Console.Error.WriteLine("  DataProtectorWebBridge.exe server [http://+:17643/] [webRoot]");
            Console.Error.WriteLine("  DataProtectorWebBridge.exe agent http://<server-ip>:17643/ [pollSeconds]");
            Console.Error.WriteLine("  DataProtectorWebBridge.exe standalone [http://+:17643/] [webRoot]");
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
