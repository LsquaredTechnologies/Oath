namespace Lsquared.Extensions.OpenAuth.OTP
{
    /// <summary>
    /// Contains different windows to use in OTP verification.
    /// </summary>
    public static class VerificationWindows
    {
        /// <summary>
        /// Gets the single window without delay.
        /// </summary>
        public static readonly VerificationWindow Single = new VerificationWindow();

        /// <summary>
        /// Gets the RFC window with network delay.
        /// </summary>
        public static readonly VerificationWindow RfcSpecifiedNetworkDelay = new VerificationWindow(previous: 1, future: 1);
    }
}
