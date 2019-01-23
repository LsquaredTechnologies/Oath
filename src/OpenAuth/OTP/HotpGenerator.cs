using System;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    /// <summary>
    /// Represents the HOTP generator defined in RFC-4226.
    /// </summary>
    /// <remarks>
    /// Based on RFC-4226 [https://tools.ietf.org/html/rfc4226]
    /// </remarks>
    public class HotpGenerator : OtpGenerator<int>
    {
        /// <summary>
        /// Creates a new instance of <see cref="TotpGenerator"/>.
        /// </summary>
        /// <param name="options">The options to use to generate codes.</param>
        public HotpGenerator(OtpGeneratorOptions options)
            : base(options)
        {
        }

        /// <inheritdoc />
        protected override long Map(int counter) =>
            counter;

        /// <inheritdoc />
        protected override int Map(long counter) =>
            (int)counter;
    }
}
