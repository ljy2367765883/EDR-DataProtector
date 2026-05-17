using System;
using System.Globalization;
using System.Net;
using System.Threading;

namespace DataProtectorWebBridge.Services
{
    internal sealed class HttpBridgeServer : IDisposable
    {
        private readonly HttpListener listener = new HttpListener();
        private readonly PolicyBridgeService policyService;
        private readonly AuditLog auditLog;
        private readonly StaticWebContent staticWebContent;
        private bool disposed;

        public HttpBridgeServer(string prefix, PolicyBridgeService policyService, AuditLog auditLog, string webRoot)
        {
            if (string.IsNullOrWhiteSpace(prefix))
            {
                throw new ArgumentException("A listener prefix is required.", "prefix");
            }

            this.policyService = policyService ?? throw new ArgumentNullException("policyService");
            this.auditLog = auditLog ?? throw new ArgumentNullException("auditLog");
            staticWebContent = new StaticWebContent(webRoot);
            listener.Prefixes.Add(prefix);
            Prefix = prefix;
        }

        public string Prefix { get; private set; }

        public void Start()
        {
            listener.Start();
            Console.WriteLine("DataProtector Web Bridge listening on " + Prefix);

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
                    JsonResponse.Write(context.Response, "0000", "Success.", policyService.GetStatus());
                    return;
                }

                if (method == "GET" && path == "/api/policy/rules")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", policyService.QueryRules());
                    return;
                }

                if (method == "POST" && path == "/api/policy/rules")
                {
                    PolicyBridgeService.PolicyRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.PolicyRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = policyService.AddRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/policy/rules")
                {
                    PolicyBridgeService.PolicyRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.PolicyRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = policyService.RemoveRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/policy/clear")
                {
                    PolicyBridgeService.OperationResult result = policyService.ClearRules(context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "GET" && path == "/api/network/rules")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", policyService.QueryNetworkRules());
                    return;
                }

                if (method == "POST" && path == "/api/network/rules")
                {
                    PolicyBridgeService.NetworkRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.NetworkRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = policyService.AddNetworkRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/network/rules")
                {
                    PolicyBridgeService.NetworkRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.NetworkRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = policyService.RemoveNetworkRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/network/clear")
                {
                    PolicyBridgeService.OperationResult result = policyService.ClearNetworkRules(context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "GET" && path == "/api/webshell/rules")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", policyService.QueryWebShellRules());
                    return;
                }

                if (method == "POST" && path == "/api/webshell/rules")
                {
                    PolicyBridgeService.WebShellRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.WebShellRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = policyService.AddWebShellRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/webshell/rules")
                {
                    PolicyBridgeService.WebShellRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.WebShellRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = policyService.RemoveWebShellRule(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "POST" && path == "/api/webshell/clear")
                {
                    PolicyBridgeService.OperationResult result = policyService.ClearWebShellRules(context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "GET" && path == "/api/hashprotect/policy")
                {
                    JsonResponse.Write(context.Response, "0000", "Success.", policyService.QueryHashProtectPolicy());
                    return;
                }

                if (method == "POST" && path == "/api/hashprotect/policy")
                {
                    PolicyBridgeService.HashProtectPolicyRequest request =
                        JsonResponse.Read<PolicyBridgeService.HashProtectPolicyRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = policyService.SetHashProtectPolicy(request);
                    JsonResponse.Write(context.Response, result.succeeded ? "0000" : result.statusText, result.message, result);
                    return;
                }

                if (method == "GET" && path == "/api/audit/events")
                {
                    try
                    {
                        policyService.DrainSecurityAuditRecords();
                    }
                    catch
                    {
                    }

                    JsonResponse.Write(context.Response, "0000", "Success.", auditLog.Read(ParseAuditQuery(context.Request)));
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
