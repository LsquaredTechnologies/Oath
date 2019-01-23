using System.Collections.Generic;

namespace Lsquared.Extensions.OpenAuth.OTP
{
    // Credits: https://github.com/kspearrin/Otp.NET/blob/master/src/Otp.NET/VerificationWindow.cs
    /// <summary>
    /// Represents a verification window used in OTP verification.
    /// </summary>
    public class VerificationWindow
    {
        /// <summary>
        /// Creates an instance of <see cref="VerificationWindow"/>.
        /// </summary>
        /// <param name="previous"></param>
        /// <param name="future"></param>
        public VerificationWindow(int previous = 0, int future = 0)
        {
            _previous = previous;
            _future = future;
        }

        /// <summary>
        /// Get all the candidates to perform OTP validation.
        /// </summary>
        /// <param name="initialFrame">The initial frame.</param>
        /// <returns>
        /// An enumerable of all windows to test in OTP validation.
        /// </returns>
        public IEnumerable<long> ValidationCandidates(long initialFrame)
        {
            yield return initialFrame;
            for (var i = 1; i <= _previous; i++)
            {
                var val = initialFrame - i;
                if (val < 0)
                    break;
                yield return val;
            }

            for (var i = 1; i <= _future; i++)
                yield return initialFrame + i;
        }

        private readonly int _previous;
        private readonly int _future;
    }
}
