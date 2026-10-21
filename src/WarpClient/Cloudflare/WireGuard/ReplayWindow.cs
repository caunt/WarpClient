namespace Warp.Cloudflare.WireGuard;

/// <summary>
/// Sliding-window replay protection for transport counters (RFC 6479, with one 64-bit word). Callers check a counter only
/// after the packet authenticated, so forged counters cannot move the window.
/// </summary>
internal sealed class ReplayWindow
{
    private const int WindowSize = 64;

    private ulong _highest;
    private ulong _seen;
    private bool _started;

    public bool TryAccept(ulong counter)
    {
        if (!_started || counter > _highest)
        {
            ulong shift = _started ? counter - _highest : WindowSize;

            _seen = shift >= WindowSize ? 1 : (_seen << (int)shift) | 1;
            _highest = counter;
            _started = true;

            return true;
        }

        ulong age = _highest - counter;

        if (age >= WindowSize)
            return false;

        ulong bit = 1UL << (int)age;

        if ((_seen & bit) != 0)
            return false;

        _seen |= bit;

        return true;
    }
}
