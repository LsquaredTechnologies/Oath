namespace Lsquared.Extensions.OpenAuth.OCRA
{
    /// <summary>
    /// Represents the internal state of <see cref="OcraGenerator"/>.
    /// </summary>
    internal sealed class OcraParameters
    {
        /// <summary>
        /// Get or sets the counter length.
        /// </summary>
        public int CounterLength { get; set; }

        /// <summary>
        /// Get or sets the question length.
        /// </summary>
        public int QuestionLength { get; set; }

        /// <summary>
        /// Get or sets the password length.
        /// </summary>
        public int PasswordLength { get; set; }

        /// <summary>
        /// Get or sets the session length.
        /// </summary>
        public int SessionLength { get; set; }

        /// <summary>
        /// Get or sets the timestamp length.
        /// </summary>
        public int TimestampLength { get; set; }

        /// <summary>
        /// Gets or sets the cryptographic function to hash.
        /// </summary>
        public CryptoFunction Hash { get; set; }

        /// <summary>
        /// Get or sets the code/PIN length.
        /// </summary>
        public int CodeLength { get; set; }

        /// <summary>
        /// Gets or sets the OCRA-suite representation.
        /// </summary>
        internal string Suite { get; set; }
    }
}
