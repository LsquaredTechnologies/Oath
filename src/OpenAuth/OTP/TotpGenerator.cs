using System;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    /// <summary>
    /// Represents the TOTP generator defined in RFC-6238.
    /// </summary>
    /// <remarks>
    /// Based on RFC-6238 [https://tools.ietf.org/html/rfc6238].
    /// </remarks>
    public class TotpGenerator : OtpGenerator<DateTimeOffset>
    {
        /// <summary>
        /// Creates a new instance of <see cref="TotpGenerator"/>.
        /// </summary>
        /// <param name="options">The options to use to generate codes.</param>
        public TotpGenerator(TotpGeneratorOptions options)
            : base(options)
        {
            _options = options;
        }

        /// <summary>
        /// Generates a new code.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <returns>
        /// A string representation of a X-digits code/PIN.
        /// </returns>
        public string Generate(byte[] privateKey)
        {
            return base.Generate(privateKey, _options.TimeProvider.UtcNow);
        }

        /// <summary>
        /// Verifies that the specified code is valid based on different parameters.
        /// </summary>
        /// <param name="code">The code to verify.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="window">The window frames to allow delay between generation and verification.</param>
        /// <param name="matchedStep">The matched step if any.</param>
        /// <returns>
        /// <c>true</c> if code is valid; otherwise, <c>false</c>.
        /// </returns>
        public bool Verify(string code, byte[] privateKey, VerificationWindow window, out DateTimeOffset matchedStep)
        {
            return base.Verify(code, privateKey, _options.TimeProvider.UtcNow, window, out matchedStep);
        }

        /// <inheritdoc />
        protected override long Map(DateTimeOffset counter) =>
            (long)(counter.ToUniversalTime().ToUnixTimeSeconds() / _options.TimeStep.TotalSeconds);

        /// <inheritdoc />
        protected override DateTimeOffset Map(long counter) =>
            UnixEpoch.AddSeconds(counter * _options.TimeStep.TotalSeconds);

        private static readonly DateTimeOffset UnixEpoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);
        private readonly TotpGeneratorOptions _options;
    }
}
