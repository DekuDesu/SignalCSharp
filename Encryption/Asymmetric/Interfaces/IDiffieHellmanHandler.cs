using Microsoft.Extensions.Logging;
using System.Security.Cryptography;

namespace DingoAuthentication.Encryption
{
    public interface IDiffieHellmanHandler
    {
        /// <summary>
        /// Gets or Sets the Diffie Hellman Key Derivation Function used by the algorithm
        /// </summary>
        ECDiffieHellmanKeyDerivationFunction ECDHKDF { get; set; }

        CngAlgorithm HashingAlgorithm { get; set; }

        CngKeyBlobFormat KeyBlobFormat { get; set; }

        int KeySize { get; set; }

        /// <summary>
        /// Generates new keys 
        /// </summary>
        /// <returns></returns>
        (byte[] PublicKey, byte[] PrivateKey) GenerateKeys();
        bool TryCreateSharedSecret<T>(ref byte[] PublicKey, ref byte[] PrivateKey, byte[] KeyToDeriveFrom, ILogger<T> logger);
        bool TryDeriveKey<T>(byte[] PrivateKey, byte[] KeyToDeriveFrom, out byte[] DerivedPrivateKey, ILogger<T> logger);
        bool TryGetPublicKey<T>(byte[] PrivateKey, out byte[] PublicKey, ILogger<T> logger);
    }
}