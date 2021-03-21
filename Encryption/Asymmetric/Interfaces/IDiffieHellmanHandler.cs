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

        /// <summary>
        /// The hashing algorithm used by the diffie helman handler.
        /// </summary>
        CngAlgorithm HashingAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the blob format of the public key used by the algorithm, FullPublic for Explicit curves, Public for implicit.
        /// </summary>
        CngKeyBlobFormat KeyBlobFormat { get; set; }

        /// <summary>
        /// The key size in bits that the algorithm should use for private keys, default is 256bits (32 bytes)
        /// </summary>
        int KeySize { get; set; }

        /// <summary>
        /// Generates new keys 
        /// </summary>
        /// <returns></returns>
        (byte[] PublicKey, byte[] PrivateKey) GenerateKeys();

        /// <summary>
        /// Attempts to create a secret between one set of keys and another
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="PublicKey"></param>
        /// <param name="PrivateKey"></param>
        /// <param name="KeyToDeriveFrom"></param>
        /// <param name="logger"></param>
        /// <returns></returns>
        bool TryCreateSharedSecret<T>(ref byte[] PublicKey, ref byte[] PrivateKey, byte[] KeyToDeriveFrom, ILogger<T> logger);

        /// <summary>
        /// Attempts to derive a new private key from the given set of keys
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="PrivateKey"></param>
        /// <param name="KeyToDeriveFrom"></param>
        /// <param name="DerivedPrivateKey"></param>
        /// <param name="logger"></param>
        /// <returns></returns>
        bool TryDeriveKey<T>(byte[] PrivateKey, byte[] KeyToDeriveFrom, out byte[] DerivedPrivateKey, ILogger<T> logger);

        /// <summary>
        /// Attempts to extract a public key from a private key
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="PrivateKey"></param>
        /// <param name="PublicKey"></param>
        /// <param name="logger"></param>
        /// <returns></returns>
        bool TryGetPublicKey<T>(byte[] PrivateKey, out byte[] PublicKey, ILogger<T> logger);
    }
}