using Warp;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Routes <see cref="IHttpClientBuilder"/> clients through Cloudflare WARP.
/// </summary>
public static class WarpClientHttpClientBuilderExtensions
{
    /// <summary>
    /// Makes the named or typed client open every connection through the registered <see cref="WarpClient"/>.
    /// </summary>
    /// <param name="builder">Client registration to reroute; <c>AddWarpClient</c> must also be called.</param>
    /// <returns>The same builder, so further configuration can be chained.</returns>
    public static IHttpClientBuilder UseWarpClient(this IHttpClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.ConfigurePrimaryHttpMessageHandler(static serviceProvider => serviceProvider.GetRequiredService<WarpClient>().CreateHttpMessageHandler());
    }
}
