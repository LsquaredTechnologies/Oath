using System;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    /// <summary>
    /// Represents the options used to configure HOTP & TOTP generator.
    /// </summary>
    public class OtpGeneratorOptions
    {
        /// <summary>
        /// Gets or sets the hash algorithm name to use in OTP generators.
        /// </summary>
        public string AlgorithmName { get; set; } = DefaultAlgorithmName;

        /// <summary>
        /// Gets or sets the code length.
        /// </summary>
        /// <remarks>
        /// Must be between 1 and 9 (inclusive).
        /// </remarks>
        public int CodeLength
        {
            get => _codeLength;
            set => Validate(value);
        }

        private void Validate(int codeLength)
        {
            if (codeLength < 1 || codeLength > 9) throw new ArgumentOutOfRangeException(nameof(codeLength), "code length must be between 1 and 9");
            _codeLength = codeLength;
        }

        private const string DefaultAlgorithmName = "HMACSHA1";
        private int _codeLength = 8;
    }
}
