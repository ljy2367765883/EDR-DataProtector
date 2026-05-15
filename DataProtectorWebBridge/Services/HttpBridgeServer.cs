using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Threading;

namespace DataProtectorWebBridge.Services
{
    internal sealed class HttpBridgeServer : IDisposable
    {
        private readonly HttpListener listener = new HttpListener();
        private readonly PolicyBridgeService policyService;
        private readonly AuditLog auditLog;
        private bool disposed;

        private readonly string webRoot;

        public HttpBridgeServer(string prefix, PolicyBridgeService policyService, AuditLog auditLog, string webRoot)
        {
            if (string.IsNullOrWhiteSpace(prefix))
            {
                throw new ArgumentException("A listener prefix is required.", "prefix");
            }

            this.policyService = policyService ?? throw new ArgumentNullException("policyService");
            this.auditLog = auditLog ?? throw new ArgumentNullException("auditLog");
            this.webRoot = ResolveWebRoot(webRoot);
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

                if (method == "GET" || method == "HEAD")
                {
                    ServeStaticFile(context, method == "HEAD");
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

        private void ServeStaticFile(HttpListenerContext context, bool headersOnly)
        {
            string filePath = ResolveStaticFilePath(context.Request.Url.AbsolutePath);
            if (filePath == null)
            {
                JsonResponse.WriteError(context.Response, HttpStatusCode.NotFound, "Web admin static file not found.");
                return;
            }

            byte[] bytes = File.ReadAllBytes(filePath);
            context.Response.StatusCode = (int)HttpStatusCode.OK;
            context.Response.ContentType = GetContentType(filePath);
            context.Response.ContentLength64 = bytes.Length;

            if (!headersOnly)
            {
                context.Response.OutputStream.Write(bytes, 0, bytes.Length);
            }
        }

        private string ResolveStaticFilePath(string absolutePath)
        {
            if (string.IsNullOrWhiteSpace(webRoot) || !Directory.Exists(webRoot))
            {
                return null;
            }

            string relativePath = Uri.UnescapeDataString((absolutePath ?? string.Empty).TrimStart('/'))
                .Replace('/', Path.DirectorySeparatorChar);

            if (string.IsNullOrWhiteSpace(relativePath))
            {
                relativePath = "index.html";
            }

            string candidate = Path.GetFullPath(Path.Combine(webRoot, relativePath));
            string normalizedRoot = Path.GetFullPath(webRoot);
            if (!normalizedRoot.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
            {
                normalizedRoot += Path.DirectorySeparatorChar;
            }

            if (!candidate.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            if (File.Exists(candidate))
            {
                return candidate;
            }

            string fallback = Path.Combine(normalizedRoot, "index.html");
            return File.Exists(fallback) ? fallback : null;
        }

        private static string ResolveWebRoot(string configuredWebRoot)
        {
            string baseDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string value = string.IsNullOrWhiteSpace(configuredWebRoot) ? "web" : configuredWebRoot;
            return Path.IsPathRooted(value) ? value : Path.GetFullPath(Path.Combine(baseDirectory, value));
        }

        private static string GetContentType(string filePath)
        {
            string extension = Path.GetExtension(filePath).ToLowerInvariant();
            switch (extension)
            {
                case ".html":
                    return "text/html; charset=utf-8";
                case ".js":
                    return "application/javascript; charset=utf-8";
                case ".css":
                    return "text/css; charset=utf-8";
                case ".json":
                    return "application/json; charset=utf-8";
                case ".svg":
                    return "image/svg+xml";
                case ".png":
                    return "image/png";
                case ".jpg":
                case ".jpeg":
                    return "image/jpeg";
                case ".ico":
                    return "image/x-icon";
                case ".woff":
                    return "font/woff";
                case ".woff2":
                    return "font/woff2";
                default:
                    return "application/octet-stream";
            }
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
