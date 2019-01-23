using System.Runtime.CompilerServices;

namespace Lsquared.Extensions.OpenAuth.Internals
{
    /// <remarks>
    /// Not intended to be used outside this assembly.
    /// </remarks>
    public static class OtpHelpers
    {
        /// <remarks>
        /// Not intended to be used outside this assembly.
        /// </sremarksummary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int DoBinaryCodeReduction(int binaryCode, int length) =>
          binaryCode % Powers[length];

        /// <remarks>
        /// Not intended to be used outside this assembly.
        /// </remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int TruncateHash(byte[] hash)
        {
            // The RFC has a hard coded index 19 in this value.
            // This is the same thing but also accommodates SHA256 and SHA512
            // hash[19] => hash[hmacComputedHash.Length - 1]
            var truncationOffset = hash[hash.Length - 1] & 0xF;
            var binaryCode =
                ((hash[truncationOffset + 0] & 0x7F) << 24) |
                ((hash[truncationOffset + 1] & 0xFF) << 16) |
                ((hash[truncationOffset + 2] & 0xFF) << 8) |
                ((hash[truncationOffset + 3] & 0xFF) << 0);
            return binaryCode;
        }

        /// <summary>
        /// Constant time comparison of two values
        /// </summary>
        /// <remarks>
        /// Not intended to be used outside this assembly.
        /// </remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool AreStringsEqual(string a, string b)
        {
            if (a.Length != b.Length)
                return false;

            var result = 0;
            for (var i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        #region Fields

        private static readonly int[] Powers =
            //          0   1    2     3      4       5        6         7          8           9
            new int[] { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };

        #endregion
    }
}
