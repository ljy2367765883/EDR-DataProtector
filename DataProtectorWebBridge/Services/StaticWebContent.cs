using System;
using System.IO;
using System.Net;
using System.Reflection;

namespace DataProtectorWebBridge.Services
{
    internal sealed class StaticWebContent
    {
        private readonly string webRoot;

        public StaticWebContent(string configuredWebRoot)
        {
            webRoot = ResolveWebRoot(configuredWebRoot);
        }

        public bool TryServe(HttpListenerContext context, bool headersOnly)
        {
            string filePath = ResolveStaticFilePath(context.Request.Url.AbsolutePath);
            if (filePath == null)
            {
                return false;
            }

            byte[] bytes = File.ReadAllBytes(filePath);
            context.Response.StatusCode = (int)HttpStatusCode.OK;
            context.Response.ContentType = GetContentType(filePath);
            context.Response.ContentLength64 = bytes.Length;

            if (!headersOnly)
            {
                context.Response.OutputStream.Write(bytes, 0, bytes.Length);
            }

            return true;
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
    }
}
