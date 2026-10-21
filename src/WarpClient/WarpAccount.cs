namespace Warp;

/// <summary>
/// The Cloudflare account a WARP device belongs to, as reported by Cloudflare's device API.
/// </summary>
/// <param name="AccountType">Plan of the account, for example <c>free</c>, <c>unlimited</c> or <c>limited</c>.</param>
/// <param name="IsWarpPlus">Whether traffic is routed over WARP+ (Argo Smart Routing) for this account.</param>
/// <param name="PremiumData">WARP+ data remaining in bytes, when the plan is metered.</param>
/// <param name="Quota">WARP+ data allowance in bytes, when the plan is metered.</param>
/// <param name="Role">This device's role in the account: <c>parent</c> for the original device, <c>child</c> after binding a license.</param>
public sealed record WarpAccount(string AccountType, bool IsWarpPlus, long PremiumData, long Quota, string Role);
