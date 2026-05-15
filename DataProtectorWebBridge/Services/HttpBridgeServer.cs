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
        private bool disposed;

        public HttpBridgeServer(string prefix, PolicyBridgeService policyService, AuditLog auditLog)
        {
            if (string.IsNullOrWhiteSpace(prefix))
            {
                throw new ArgumentException("A listener prefix is required.", "prefix");
            }

            this.policyService = policyService ?? throw new ArgumentNullException("policyService");
            this.auditLog = auditLog ?? throw new ArgumentNullException("auditLog");
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
                    JsonResponse.Write(context.Response, result.Succeeded ? "0000" : result.StatusText, result.Message, result);
                    return;
                }

                if (method == "DELETE" && path == "/api/policy/rules")
                {
                    PolicyBridgeService.PolicyRuleRequest request =
                        JsonResponse.Read<PolicyBridgeService.PolicyRuleRequest>(context.Request.InputStream);
                    PolicyBridgeService.OperationResult result = policyService.RemoveRule(request);
                    JsonResponse.Write(context.Response, result.Succeeded ? "0000" : result.StatusText, result.Message, result);
                    return;
                }

                if (method == "POST" && path == "/api/policy/clear")
                {
                    PolicyBridgeService.OperationResult result = policyService.ClearRules(context.Request.UserHostAddress);
                    JsonResponse.Write(context.Response, result.Succeeded ? "0000" : result.StatusText, result.Message, result);
                    return;
                }

                if (method == "GET" && path == "/api/audit/events")
                {
                    int limit = ParseLimit(context.Request.QueryString["limit"]);
                    JsonResponse.Write(context.Response, "0000", "Success.", auditLog.ReadRecent(limit));
                    return;
                }

                JsonResponse.WriteError(context.Response, HttpStatusCode.NotFound, "API route not found.");
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

        private static void AddCorsHeaders(HttpListenerResponse response)
        {
            response.Headers["Access-Control-Allow-Origin"] = "http://localhost:9527";
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
