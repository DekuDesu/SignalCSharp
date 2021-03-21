using System.Security.Cryptography;

namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Handles the signing and verifcation of cryptographically signed data
    /// </summary>
    public interface ISignatureHandler
    {
        /// <summary>
        /// The hash algorithm that should be used to sign the data
        /// </summary>
        CngAlgorithm HashAlgorithm { get; set; }

        /// <summary>
        /// The key size that the algorithm that should be used in bits. default is normally 256bits / or 32 bytes
        /// </summary>
        int KeySize { get; set; }

        /// <summary>
        /// Attempts to sign the data using the provided <paramref name="PrivateKey"/> and out puts the <paramref name="X509PublicKey"/> that can be used to verify the data
        /// </summary>
        /// <param name="DataToSign"></param>
        /// <param name="PrivateKey"></param>
        /// <param name="Signature"></param>
        /// <param name="X509PublicKey"></param>
        /// <returns></returns>
        bool TrySign(byte[] DataToSign, byte[] PrivateKey, out byte[] Signature, out byte[] X509PublicKey);

        /// <summary>
        /// Attempts to verify the given data using the provided IdentityKey and Signature
        /// </summary>
        /// <param name="SignedData"></param>
        /// <param name="Signature"></param>
        /// <param name="X509PublicKey"></param>
        /// <returns></returns>
        bool Verify(byte[] SignedData, byte[] Signature, byte[] X509PublicKey);
    }
}