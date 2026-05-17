using System;
using System.Globalization;
using System.Net;
using System.Threading;

namespace DataProtectorWebBridge.Services
{
    internal sealed class CentralHttpServer : IDisposable
    {
        private readonly HttpListener listener = new HttpListener();
        private readonly CentralPolicyStore store;
        private readonly StaticWebContent staticWebContent;
        private bool disposed;

        public CentralHttpServer(string prefix, CentralPolicyStore store, string webRoot)
        {
            if (string.IsNullOrWhiteSpace(prefix))
            {
                throw new ArgumentException("A listener prefix is required.", "prefix");
            }

            this.store = store ?? throw new ArgumentNullException("store");
            staticWebContent = new StaticWebContent(webRoot);
            listener.Prefixes.Add(prefix);
            Prefix = prefix;
        }

        public string Prefix { get; private set; }

        public void Start()
        {
            listener.Start();
            Console.WriteLine("DataProtector Central Server listening on " + Prefix);
            Console.WriteLine("Central state: " + store.FilePath);

            while (listener.IsListening)
            {
                HttpListenerContext context = listener.GetContext();
                ThreadPool.QueueUserWorkItem(_ => HandleContext(context));
            }
        }

        private void HandleContext(HttpListenerContext context)
        {
            try
            {
                AddCorsHeaders(context.Response);

                if (context.Request.HttpMethod.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.StatusCode = (int)HttpStatusCode.NoContent;
                    return;
                }

                string path = context.Request.Url.AbsolutePath.TrimEnd('/').ToLowerInvariant();
                string method = context.Request.HttpMethod.ToUpperInvariant();

                if (method == "GET" && path == "/api/status")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.GetStatus());
                    return;
                }

                if (method == "GET" && path == "/api/devices")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryDevices());
                    return;
                }

                if (method == "GET" && path == "/api/tasks")
                {
                    int limit = ParseLimit(context.Request.QueryString["limit"]);
                    string deviceId = context.Request.QueryString["deviceId"];
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryTasks(deviceId, limit));
                    return;
                }

                if (method == "POST" && path == "/api/tasks")
                {
                    CentralPolicyStore.RemoteTaskRequest request =
                        JsonResponse.Read<CentralPolicyStore.RemoteTaskRequest>(context.Request.InputStream);
                    JsonResponse.Write(context.Response, "0000", "Remote task queued.", store.CreateTask(request));
                    return;
                }

                if (method == "GET" && path == "/api/policy/rules")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryRules());
                    return;
                }

                if (method == "POST" && path == "/api/policy/rules")
                {
                    PolicyBridgeService.PolicyRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.PolicyRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.AddRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/policy/rules")
                {
                    PolicyBridgeService.PolicyRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.PolicyRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.RemoveRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/policy/clear")
                {
                    PolicyBridgeService.OperationResult result = store.ClearRules(context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "GET" && path == "/api/network/rules")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryNetworkRules());
                    return;
                }

                if (method == "GET" && path == "/api/network/insights")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryNetworkInsights(ParseNetworkInsightQuery(context.Request)));
                    return;
                }

                if (method == "GET" && path == "/api/network/ipinfo/config")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryIpInfoConfiguration());
                    return;
                }

                if (method == "POST" && path == "/api/network/ipinfo/config")
                {
                    CentralPolicyStore.IpInfoConfigurationRequest request =
                        JsonResponse.Read<CentralPolicyStore.IpInfoConfigurationRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.SaveIpInfoConfiguration(request, context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/network/ipinfo/config")
                {
                    PolicyBridgeService.OperationResult result = store.ClearIpInfoConfiguration(context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/network/rules")
                {
                    PolicyBridgeService.NetworkRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.NetworkRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.AddNetworkRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/network/rules")
                {
                    PolicyBridgeService.NetworkRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.NetworkRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.RemoveNetworkRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/network/clear")
                {
                    PolicyBridgeService.OperationResult result = store.ClearNetworkRules(context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "GET" && path == "/api/webshell/rules")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryWebShellRules());
                    return;
                }

                if (method == "GET" && path == "/api/device/rules")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryDeviceRules());
                    return;
                }

                if (method == "GET" && path == "/api/device/removable")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryRemovableDevices());
                    return;
                }

                if (method == "POST" && path == "/api/webshell/rules")
                {
                    PolicyBridgeService.WebShellRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.WebShellRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.AddWebShellRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/device/rules")
                {
                    PolicyBridgeService.DeviceRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.DeviceRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.AddDeviceRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/device/removable/authorization")
                {
                    CentralPolicyStore.RemovableDeviceAuthorizationRequest request =
                        JsonResponse.Read<CentralPolicyStore.RemovableDeviceAuthorizationRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.AuthorizeRemovableDevice(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/webshell/rules")
                {
                    PolicyBridgeService.WebShellRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.WebShellRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.RemoveWebShellRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/device/rules")
                {
                    PolicyBridgeService.DeviceRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.DeviceRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.RemoveDeviceRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/device/removable/authorization")
                {
                    CentralPolicyStore.RemovableDeviceAuthorizationRequest request =
                        JsonResponse.Read<CentralPolicyStore.RemovableDeviceAuthorizationRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.RemoveRemovableDeviceAuthorization(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/webshell/clear")
                {
                    PolicyBridgeService.OperationResult result = store.ClearWebShellRules(context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/device/clear")
                {
                    PolicyBridgeService.OperationResult result = store.ClearDeviceRules(context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "GET" && path == "/api/hashprotect/policy")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryHashProtectPolicy());
                    return;
                }

                if (method == "POST" && path == "/api/hashprotect/policy")
                {
                    PolicyBridgeService.HashProtectPolicyRequest request =
                        JsonResponse.Read<PolicyBridgeService.HashProtectPolicyRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.UpdateHashProtectPolicy(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "GET" && path == "/api/lateral/policy")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryLateralDefensePolicy());
                    return;
                }

                if (method == "POST" && path == "/api/lateral/policy")
                {
                    PolicyBridgeService.LateralDefensePolicyRequest request =
                        JsonResponse.Read<PolicyBridgeService.LateralDefensePolicyRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = store.UpdateLateralDefensePolicy(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "GET" && path == "/api/audit/events")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", store.QueryAudit(ParseAuditQuery(context.Request)));
                    return;
                }

                if (method == "POST" && path == "/api/agent/sync")
                {
                    CentralPolicyStore.AgentSyncRequest request =
                        JsonResponse.Read<CentralPolicyStore.AgentSyncRequest>(context.Request.InputStream);
                    JsonResponse.Write(context.Response, "0000", "Success.", store.SyncAgent(request));
                    return;
                }

                if (method == "GET" || method == "HEAD")
                {
                    if (!staticWebContent.TryServe(context, method == "HEAD"))
                    {
                        JsonResponse.WriteError(context.Response, HttpStatusCode.NotFound, "Web admin static file not found.");
                    }

                    return;
                }

                JsonResponse.WriteError(context.Response, HttpStatusCode.NotFound, "Route not found.");
            }
            catch (PolicyBridgeService.BridgeException ex)
            {
                JsonResponse.Write(context.Response, "0x" + ex.Status.ToString("X8"), ex.Message, null);
            }
            catch (Exception ex)
            {
                JsonResponse.WriteError(context.Response, HttpStatusCode.InternalServerError, ex.Message);
            }
            finally
            {
                context.Response.OutputStream.Close();
            }
        }

        private static int ParseLimit(string value)
        {
            int limit;
            if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out limit))
            {
                return 200;
            }

            return Math.Max(1, Math.Min(limit, 1000));
        }

        private static AuditLog.AuditQueryOptions ParseAuditQuery(HttpListenerRequest request)
        {
            return new AuditLog.AuditQueryOptions
            {
                Limit = ParseLimit(request.QueryString["limit"]),
                Category = request.QueryString["category"],
                Host = request.QueryString["host"],
                Result = request.QueryString["result"],
                Severity = request.QueryString["severity"],
                Disposition = request.QueryString["disposition"],
                FromUtc = request.QueryString["fromUtc"],
                ToUtc = request.QueryString["toUtc"],
                Search = request.QueryString["search"]
            };
        }

        private static CentralPolicyStore.NetworkInsightQuery ParseNetworkInsightQuery(HttpListenerRequest request)
        {
            return new CentralPolicyStore.NetworkInsightQuery
            {
                limit = ParseLimit(request.QueryString["limit"]),
                baselineHours = ParseHours(request.QueryString["baselineHours"], 24),
                windowHours = ParseHours(request.QueryString["windowHours"], 24 * 31),
                host = request.QueryString["host"],
                eventType = request.QueryString["eventType"],
                search = request.QueryString["search"],
                includePrivateRemotes = ParseBoolean(request.QueryString["includePrivateRemotes"])
            };
        }

        private static bool ParseBoolean(string value)
        {
            return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase);
        }

        private static int ParseHours(string value, int fallback)
        {
            int hours;
            if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out hours))
            {
                return fallback;
            }

            return Math.Max(1, Math.Min(hours, 24 * 31));
        }

        private static void AddCorsHeaders(HttpListenerResponse response)
        {
            response.Headers["Access-Control-Allow-Origin"] = "*";
            response.Headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS";
            response.Headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
        }

        public void Dispose()
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            listener.Close();
        }
    }
}
