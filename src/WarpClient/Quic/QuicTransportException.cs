namespace Warp.Quic;

/// <summary>
/// A QUIC connection error: either one this client detected and reports to the server, or the reason the server gave when it
/// closed the connection.
/// </summary>
internal sealed class QuicTransportException : IOException
{
    public const ulong ApplicationError = 0x0C;
    public const ulong ConnectionIdLimitError = 0x09;
    public const ulong CryptoBufferExceeded = 0x0D;
    public const ulong CryptoErrorBase = 0x100;
    public const ulong FinalSizeError = 0x06;
    public const ulong FlowControlError = 0x03;
    public const ulong FrameEncodingError = 0x07;
    public const ulong InternalError = 0x01;
    public const ulong NoError = 0x00;
    public const ulong ProtocolViolation = 0x0A;
    public const ulong StreamLimitError = 0x04;
    public const ulong StreamStateError = 0x05;
    public const ulong TransportParameterError = 0x08;

    public QuicTransportException()
    {
    }

    public QuicTransportException(string message)
        : base(message)
    {
    }

    public QuicTransportException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public QuicTransportException(ulong errorCode, string message, bool isApplicationError = false)
        : base(message)
    {
        ErrorCode = errorCode;
        IsApplicationError = isApplicationError;
    }

    public ulong ErrorCode { get; } = InternalError;

    public bool IsApplicationError { get; }
}
