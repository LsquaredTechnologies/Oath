using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Lsquared.Extensions.OpenAuth.Internals;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    /// <summary>
    /// Represents the base implementation of OTP generation.
    /// </summary>
    /// <typeparam name="T">The counter type.</typeparam>
    public abstract class OtpGenerator<T>
        where T : struct
    {
        /// <summary>
        /// Creates a new instance of <see cref="OtpGenerator{T}"/>.
        /// </summary>
        /// <param name="options">The options to use to generate codes.</param>
        protected OtpGenerator(OtpGeneratorOptions options)
        {
            _options = options;
        }

        /// <summary>
        /// Generates a new code.
        /// </summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="counter">The counter.</param>
        /// <returns>
        /// A string representation of a X-digits code/PIN.
        /// </returns>
        public string Generate(byte[] privateKey, T counter) =>
            Generate(privateKey, Map(counter));

        /// <summary>
        /// Verifies that the specified code is valid based on different parameters.
        /// </summary>
        /// <param name="code">The code to verify.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="initialStep">The initial step.</param>
        /// <param name="window">The window frames to allow delay between generation and verification.</param>
        /// <param name="matchedStep">The matched step if any.</param>
        /// <returns>
        /// <c>true</c> if code is valid; otherwise, <c>false</c>.
        /// </returns>
        public bool Verify(string code, byte[] privateKey, T initialStep, VerificationWindow window, out T matchedStep)
        {
            matchedStep = Map(0);
            var initialCounter = Map(initialStep);
            foreach (var frame in window.ValidationCandidates(initialCounter))
            {
                var comparisonValue = Generate(privateKey, frame);
                if (OtpHelpers.AreStringsEqual(comparisonValue, code))
                {
                    matchedStep = Map(frame);
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Maps the counter specific-type to <c>long</c>.
        /// </summary>
        /// <param name="counter">The counter.</param>
        /// <returns>
        /// The <c>long</c> representation of the counter.
        /// </returns>
        protected abstract long Map(T counter);

        /// <summary>
        /// Maps a <c>long</c> counter to the counter specific-type.
        /// </summary>
        /// <param name="counter">The counter.</param>
        /// <returns>
        /// The <typeparamref name="T"/> representation of the counter.
        /// </returns>
        protected abstract T Map(long counter);

        /// <summary>
        /// Converts the <c>long</c>-value counter to <c>byte[]</c>.
        /// </summary>
        /// <param name="counter">The counter.</param>
        /// <returns>
        /// The <c>byte</c> array representation of the counter.
        /// </returns>
        protected virtual byte[] ToByteArray(long counter)
        {
            var buffer = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian) Array.Reverse(buffer);
            return buffer;
        }

        #region Helpers

        private string Generate(byte[] privateKey, long counter)
        {
            var hash = HmacHash(privateKey, ToByteArray(counter));
            var code = ComputeDigits(hash);
            return code;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private string ComputeDigits(byte[] hash)
        {
            // Same code as in OcraGenerator.
            var binaryCode = OtpHelpers.TruncateHash(hash);
            var otpCode = OtpHelpers.DoBinaryCodeReduction(binaryCode, _options.CodeLength);
            return otpCode.ToString(CultureInfo.InvariantCulture).PadLeft(_options.CodeLength, '0');
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private byte[] HmacHash(byte[] privateKey, byte[] counter)
        {
            using (var hasher = HMAC.Create(_options.AlgorithmName))
            {
                hasher.Key = privateKey;
                return hasher.ComputeHash(counter);
            }
        }

        #endregion

        #region Fields

        private readonly OtpGeneratorOptions _options;

        #endregion
    }
}
