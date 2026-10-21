using Microsoft.Extensions.DependencyInjection.Extensions;

using Warp;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers <see cref="WarpClient"/> so services can reach the internet through Cloudflare WARP.
/// </summary>
public static class WarpClientServiceCollectionExtensions
{
    /// <summary>
    /// Registers one shared <see cref="WarpClient"/> and exposes it as <see cref="ITcpConnector"/> and <see cref="IUdpConnector"/>.
    /// The tunnel opens on first use and closes when the container is disposed asynchronously.
    /// </summary>
    /// <param name="services">Container that receives the registrations.</param>
    /// <param name="configureOptions">Adjusts where credentials are stored or how Cloudflare is reached; defaults apply when omitted.</param>
    /// <returns>The same collection, so further registrations can be chained.</returns>
    public static IServiceCollection AddWarpClient(this IServiceCollection services, Action<WarpClientOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(
            serviceProvider =>
            {
                WarpClientOptions options = new();

                configureOptions?.Invoke(options);

                return new WarpClient(options);
            }
        );

        services.TryAddSingleton<ITcpConnector>(serviceProvider => serviceProvider.GetRequiredService<WarpClient>());
        services.TryAddSingleton<IUdpConnector>(serviceProvider => serviceProvider.GetRequiredService<WarpClient>());

        return services;
    }
}
