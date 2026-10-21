using Warp.Quic.Buffers;

namespace Warp.Quic;

/// <summary>
/// One QUIC stream's send and receive halves (RFC 9000 section 3) with their flow-control limits and abort state.
/// </summary>
internal sealed class QuicStreamState(long id, long sendLimit, long receiveWindow)
{
    public bool CanReceive => IsBidirectional || !IsLocal;

    public bool CanSend => IsBidirectional || IsLocal;

    public long? FinalSize { get; set; }

    public bool HasPendingSend => CanSend && ResetCode is null && Send.HasPendingData;

    public long Id => id;

    public bool IsBidirectional => (id & 0x2) == 0;

    public bool IsLocal => (id & 0x1) == 0;

    public bool IsReadComplete => FinalSize is long finalSize && Receive.ReadOffset == finalSize;

    public bool IsReceiveDone => !CanReceive || ReadAborted || PeerResetCode is not null || IsReadComplete;

    public bool IsReleased { get; set; }

    public bool IsSendDone => !CanSend || Send.IsFullyAcknowledged || ResetAcknowledged;

    public bool MaximumStreamDataPending { get; set; }

    public ulong? PeerResetCode { get; set; }

    public ulong? PeerStopSendingCode { get; set; }

    public bool ReadAborted { get; set; }

    public ReassemblyBuffer Receive { get; } = new();

    public long ReceiveLimit { get; set; } = receiveWindow;

    public long ReceiveWindow { get; } = receiveWindow;

    public bool ResetAcknowledged { get; set; }

    public ulong? ResetCode { get; set; }

    public bool ResetPending { get; set; }

    public SendBuffer Send { get; } = new();

    public long SendLimit { get; set; } = sendLimit;

    public ulong StopSendingCode { get; set; }

    public bool StopSendingPending { get; set; }

    public void AbortWrite(ulong errorCode)
    {
        if (!CanSend || ResetCode is not null || Send.IsFullyAcknowledged)
            return;

        ResetCode = errorCode;
        ResetPending = true;
    }

    public void CompleteWrites()
    {
        if (CanSend && ResetCode is null)
            Send.Finish();
    }

    public void Write(ReadOnlySpan<byte> data)
    {
        if (PeerStopSendingCode is ulong code)
            throw new QuicTransportException(code, $"The server stopped reading stream {Id} with error 0x{code:X}.", isApplicationError: true);

        if (!CanSend || ResetCode is not null || Send.FinRequested)
            throw new InvalidOperationException(message: "Writing to this stream has already been completed or aborted.");

        Send.Write(data);
    }
}
