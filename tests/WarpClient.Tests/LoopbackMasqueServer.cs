using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Warp.Tests;

/// <summary>
/// Plays the part of Cloudflare's HTTP/2 MASQUE endpoint on loopback: it presents the pinned server key, accepts the
/// <c>CONNECT</c> stream with a 200 and then keeps the connection open until the test closes it.
/// </summary>
internal sealed class LoopbackMasqueServer : IAsyncDisposable
{
    private const byte AcknowledgeFlag = 0x1;
    private const byte EndHeadersFlag = 0x4;
    private const int FrameHeaderLength = 9;
    private const byte HeadersFrame = 0x1;
    private const int PrefaceLength = 24;
    private const byte SettingsFrame = 0x4;
    private const byte StatusOk = 0x88;

    private readonly Task _accepting;
    private readonly X509Certificate2 _certificate;
    private readonly ConcurrentQueue<SslStream> _connections = new();
    private readonly TcpListener _listener = new(IPAddress.Loopback, port: 0);
    private readonly ConcurrentQueue<Task> _serving = new();
    private readonly CancellationTokenSource _stopping = new();

    public LoopbackMasqueServer(ECDsa serverKey)
    {
        CertificateRequest request = new(subjectName: "CN=loopback", serverKey, HashAlgorithmName.SHA256);

        using X509Certificate2 ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(days: -1), DateTimeOffset.UtcNow.AddDays(days: 1));

        // Windows cannot authenticate a server with the ephemeral key of a fresh certificate; reloading it from PKCS#12 makes it usable.
        _certificate = X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), password: null);
        _listener.Start();
        _accepting = AcceptAsync(_stopping.Token);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public void CloseConnections()
    {
        while (_connections.TryDequeue(out SslStream? connection))
            connection.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);
        _listener.Stop();
        _listener.Dispose();
        CloseConnections();
        await _accepting.ConfigureAwait(continueOnCapturedContext: false);

        while (_serving.TryDequeue(out Task? serving))
            await serving.ConfigureAwait(continueOnCapturedContext: false);

        _certificate.Dispose();
        _stopping.Dispose();
    }

    private static async ValueTask WriteFrameAsync(Stream stream, byte type, byte flags, int streamIdentifier, byte[] payload, CancellationToken cancellationToken)
    {
        byte[] frame = new byte[FrameHeaderLength + payload.Length];

        frame[0] = (byte)(payload.Length >> 16);
        frame[1] = (byte)(payload.Length >> 8);
        frame[2] = (byte)payload.Length;
        frame[3] = type;
        frame[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(start: 5), streamIdentifier);
        payload.CopyTo(frame, FrameHeaderLength);
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async Task AcceptAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                _serving.Enqueue(ServeAsync(client, cancellationToken));
            }
        }
        catch (OperationCanceledException exception)
        {
            Assert.True(cancellationToken.IsCancellationRequested, exception.Message);
        }
        catch (SocketException exception)
        {
            Assert.True(cancellationToken.IsCancellationRequested, exception.Message);
        }
    }

    private async Task ServeAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            using SslStream stream = new(client.GetStream());

            _connections.Enqueue(stream);

            try
            {
                SslServerAuthenticationOptions options = new() { ServerCertificate = _certificate, ApplicationProtocols = [SslApplicationProtocol.Http2] };

                await stream.AuthenticateAsServerAsync(options, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                await stream.ReadExactlyAsync(new byte[PrefaceLength], cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                byte[] header = new byte[FrameHeaderLength];

                while (!cancellationToken.IsCancellationRequested)
                {
                    await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                    int length = (header[0] << 16) | (header[1] << 8) | header[2];
                    int streamIdentifier = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(start: 5)) & int.MaxValue;

                    await stream.ReadExactlyAsync(new byte[length], cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                    if (header[3] == SettingsFrame && (header[4] & AcknowledgeFlag) == 0)
                    {
                        await WriteFrameAsync(stream, SettingsFrame, flags: 0, streamIdentifier: 0, [], cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                        await WriteFrameAsync(stream, SettingsFrame, AcknowledgeFlag, streamIdentifier: 0, [], cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                    }
                    else if (header[3] == HeadersFrame)
                    {
                        await WriteFrameAsync(stream, HeadersFrame, EndHeadersFlag, streamIdentifier, [StatusOk], cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                    }
                }
            }
            catch (IOException exception)
            {
                Assert.NotNull(exception);
            }
            catch (ObjectDisposedException exception)
            {
                Assert.NotNull(exception);
            }
            catch (AuthenticationException exception)
            {
                Assert.NotNull(exception);
            }
            catch (OperationCanceledException exception)
            {
                Assert.NotNull(exception);
            }
        }
    }
}
