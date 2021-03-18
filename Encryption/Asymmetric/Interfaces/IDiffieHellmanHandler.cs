using Microsoft.Extensions.Logging;
using System.Security.Cryptography;

namespace DingoAuthentication.Encryption
{
    public interface IDiffieHellmanHandler
    {
        ECDiffieHellmanKeyDerivationFunction ECDHKDF { get; set; }
        CngAlgorithm HashingAlgorithm { get; set; }
        CngKeyBlobFormat KeyBlobFormat { get; set; }
        int KeySize { get; set; }

        (byte[] PublicKey, byte[] PrivateKey) GenerateKeys();
        bool TryCreateSharedSecret<T>(ref byte[] PublicKey, ref byte[] PrivateKey, byte[] KeyToDeriveFrom, ILogger<T> logger);
    }
}