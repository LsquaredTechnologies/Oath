namespace Lsquared.Extensions.OpenAuth.OCRA
{
    /// <summary>
    /// Represents the delegate used to encrypt a specific value.
    /// </summary>
    /// <param name="privateKey">The private key.</param>
    /// <param name="buffer">The buffer to encrypt.</param>
    /// <returns>
    /// A <c>byte[]</c> representing the encrypted value.
    /// </returns>
    public delegate byte[] CryptoFunction(byte[] privateKey, byte[] buffer);
}
