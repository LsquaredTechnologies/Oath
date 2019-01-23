using System;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    internal class ConstantTimeProvider : ITimeProvider
    {
        public DateTimeOffset UtcNow { get; }

        public ConstantTimeProvider(DateTimeOffset date)
        {
            UtcNow = date;
        }
    }
}
