namespace Warp.Cloudflare.Registration;

internal sealed record AccountResponse(string? AccountType, bool WarpPlus, long PremiumData, long Quota, string? Role);
