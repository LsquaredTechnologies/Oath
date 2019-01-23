using System;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    /// <summary>
    /// Provides the contract to get date/time in TOTP generator.
    /// </summary>
    public interface ITimeProvider
    {
        /// <summary>
        /// Gets the current date/time (as UTC).
        /// </summary>
        DateTimeOffset UtcNow { get; }
    }
}
