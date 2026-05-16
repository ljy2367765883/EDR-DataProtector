using System;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Web.Script.Serialization;

namespace DataProtectorWebBridge.Services
{
    internal static class JsonResponse
    {
        private static readonly JavaScriptSerializer Serializer = CreateSerializer();

        public static JavaScriptSerializer CreateSerializer()
        {
            return new JavaScriptSerializer
            {
                MaxJsonLength = int.MaxValue,
                RecursionLimit = 256
            };
        }

        public static T Read<T>(Stream stream)
        {
            if (stream == null || !stream.CanRead)
            {
                return default(T);
            }

            using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
            {
                string json = reader.ReadToEnd();
                if (string.IsNullOrWhiteSpace(json))
                {
                    return default(T);
                }

                return Serializer.Deserialize<T>(json);
            }
        }

        public static void Write(HttpListenerResponse response, string code, string message, object data)
        {
            WriteRaw(response, HttpStatusCode.OK, new
            {
                code,
                msg = message,
                data
            });
        }

        public static void WriteError(HttpListenerResponse response, HttpStatusCode statusCode, string message)
        {
            WriteRaw(response, statusCode, new
            {
                code = ((int)statusCode).ToString(),
                msg = message,
                data = (object)null
            });
        }

        private static void WriteRaw(HttpListenerResponse response, HttpStatusCode statusCode, object payload)
        {
            string json = Serializer.Serialize(payload);
            byte[] bytes = Encoding.UTF8.GetBytes(json);

            response.StatusCode = (int)statusCode;
            response.ContentType = "application/json; charset=utf-8";
            response.ContentEncoding = Encoding.UTF8;
            response.ContentLength64 = bytes.Length;
            response.Headers["Access-Control-Allow-Origin"] = "*";
            response.Headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS";
            response.Headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
            response.OutputStream.Write(bytes, 0, bytes.Length);
        }
    }
}
