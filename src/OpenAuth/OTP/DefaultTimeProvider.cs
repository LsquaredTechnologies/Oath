using System;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    /// <summary>
    /// Represents the default date/time provider which returns the current date/time.
    /// </summary>
    public sealed class DefaultTimeProvider : ITimeProvider
    {
        /// <inheritdoc />
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    }
}
