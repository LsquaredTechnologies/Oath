using System;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    /// <summary>
    /// Represents the options used to configure TOTP generator.
    /// </summary>
    public class TotpGeneratorOptions : OtpGeneratorOptions
    {
        /// <summary>
        /// Gets or sets the time provider.
        /// </summary>
        public ITimeProvider TimeProvider { get; set; } = new DefaultTimeProvider();

        /// <summary>
        /// Gets or sets the time step.
        /// </summary>
        public TimeSpan TimeStep { get; set; } = TimeSpan.FromSeconds(30);
    }
}
