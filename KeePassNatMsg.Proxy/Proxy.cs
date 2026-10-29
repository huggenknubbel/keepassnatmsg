using System;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;

[assembly: AssemblyTitle("KeePassNatMsg Proxy")]
[assembly: AssemblyProduct("KeePassNatMsg")]
[assembly: AssemblyVersion("1.0.0")]
[assembly: AssemblyFileVersion("1.0.0")]

namespace KeePassNatMsg.Proxy
{
    /// <summary>
    /// Native messaging host started by the browser. Forwards messages between the
    /// browser (stdin/stdout with a 4 byte length prefix) and the KeePassNatMsg plugin
    /// (named pipe on Windows, unix socket on Linux and macOS).
    /// </summary>
    internal static class Proxy
    {
        private const string ServerName = "kpxc_server";
        private const int ConnectTimeout = 5000;

        private static int Main()
        {
            Stream server;
            try
            {
                server = Connect();
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Cannot connect to KeePass: " + e.Message);
                return 1;
            }

            var stdin = Console.OpenStandardInput();
            var stdout = Console.OpenStandardOutput();

            var serverToBrowser = new Thread(() => ForwardToBrowser(server, stdout)) { IsBackground = true };
            serverToBrowser.Start();

            ForwardToServer(stdin, server);
            return 0;
        }

        private static Stream Connect()
        {
            if (Environment.OSVersion.Platform == PlatformID.Unix || Environment.OSVersion.Platform == PlatformID.MacOSX)
            {
                var dir = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");
                var path = Path.Combine(string.IsNullOrEmpty(dir) ? "/tmp" : dir, ServerName);
                var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                socket.Connect(new UnixEndPoint(path));
                return new NetworkStream(socket, true);
            }

            var pipe = new NamedPipeClientStream(".", string.Format("keepassxc\\{0}\\{1}", Environment.UserName, ServerName), PipeDirection.InOut);
            pipe.Connect(ConnectTimeout);
            return pipe;
        }

        // Browser messages are passed on as raw JSON, one message per write
        private static void ForwardToServer(Stream stdin, Stream server)
        {
            var header = new byte[4];
            while (ReadExactly(stdin, header, 4))
            {
                var length = BitConverter.ToInt32(header, 0);
                if (length <= 0)
                    continue;

                var message = new byte[length];
                if (!ReadExactly(stdin, message, length))
                    break;

                server.Write(message, 0, length);
                server.Flush();
            }
        }

        // The plugin writes raw JSON objects that may arrive split or combined, so they are
        // separated by tracking the nesting depth outside of strings
        private static void ForwardToBrowser(Stream server, Stream stdout)
        {
            var buffer = new byte[64 * 1024];
            var message = new MemoryStream();
            int depth = 0;
            bool inString = false, escaped = false;
            int read;

            while ((read = server.Read(buffer, 0, buffer.Length)) > 0)
            {
                for (var i = 0; i < read; i++)
                {
                    var b = buffer[i];
                    if (depth == 0 && b != '{')
                        continue;

                    message.WriteByte(b);

                    if (inString)
                    {
                        if (escaped) escaped = false;
                        else if (b == '\\') escaped = true;
                        else if (b == '"') inString = false;
                    }
                    else if (b == '"') inString = true;
                    else if (b == '{') depth++;
                    else if (b == '}' && --depth == 0)
                    {
                        var data = message.ToArray();
                        stdout.Write(BitConverter.GetBytes(data.Length), 0, 4);
                        stdout.Write(data, 0, data.Length);
                        stdout.Flush();
                        message.SetLength(0);
                    }
                }
            }

            // KeePass was closed
            Environment.Exit(0);
        }

        private static bool ReadExactly(Stream stream, byte[] buffer, int count)
        {
            var offset = 0;
            while (offset < count)
            {
                var read = stream.Read(buffer, offset, count - offset);
                if (read <= 0)
                    return false;
                offset += read;
            }
            return true;
        }
    }

    // AF_UNIX socket address, so the proxy doesn't depend on Mono.Posix
    internal sealed class UnixEndPoint : EndPoint
    {
        private readonly string _path;

        public UnixEndPoint(string path)
        {
            _path = path;
        }

        public override AddressFamily AddressFamily
        {
            get { return AddressFamily.Unix; }
        }

        public override SocketAddress Serialize()
        {
            var path = Encoding.UTF8.GetBytes(_path);
            var address = new SocketAddress(AddressFamily.Unix, 2 + path.Length + 1);
            for (var i = 0; i < path.Length; i++)
            {
                address[2 + i] = path[i];
            }
            return address;
        }

        public override EndPoint Create(SocketAddress socketAddress)
        {
            var path = new byte[socketAddress.Size - 2];
            for (var i = 0; i < path.Length; i++)
            {
                path[i] = socketAddress[2 + i];
            }
            return new UnixEndPoint(Encoding.UTF8.GetString(path).TrimEnd('\0'));
        }

        public override string ToString()
        {
            return _path;
        }
    }
}
