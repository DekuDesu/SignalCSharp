using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{
    // this removes the warning for Windows Operating System dependancy, the DH crypto function will eventually be re-written, but for now this warning is clogging up my warnings
#pragma warning disable CA1416
    public class DiffieHellmanHandler : IDiffieHellmanHandler
    {
        private readonly ILogger<DiffieHellmanHandler> logger;

        public int KeySize { get; set; } = 256;

        public CngAlgorithm HashingAlgorithm { get; set; } = CngAlgorithm.Sha256;

        public ECDiffieHellmanKeyDerivationFunction ECDHKDF { get; set; } = ECDiffieHellmanKeyDerivationFunction.Hash;

        /// <summary>
        /// The format the public key is in, use <see cref="CngKeyBlobFormat.EccPublicBlob"/> for implicit ECCurves and <see cref="CngKeyBlobFormat.EccFullPublicBlob"/> for explicit ECCurves.
        /// </summary>
        public CngKeyBlobFormat KeyBlobFormat { get; set; } = CngKeyBlobFormat.EccPublicBlob;

        public DiffieHellmanHandler(ILogger<DiffieHellmanHandler> _logger)
        {
            logger = _logger;
        }

        public (byte[] PublicKey, byte[] PrivateKey) GenerateKeys()
        {
            if (OperatingSystem.IsWindows())
            {
                using (ECDiffieHellmanCng ECD = new ECDiffieHellmanCng(KeySize))
                {
                    var x = ECD.ExportParameters(true);

                    ECD.KeyDerivationFunction = ECDHKDF;

                    ECD.HashAlgorithm = HashingAlgorithm;

                    return (
                        ECD.PublicKey.ToByteArray(),
                        ECD.ExportECPrivateKey()
                    );
                }
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        public bool TryCreateSharedSecret<T>(ref byte[] PublicKey, ref byte[] PrivateKey, byte[] KeyToDeriveFrom, ILogger<T> logger)
        {
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    using (ECDiffieHellmanCng ECD = new ECDiffieHellmanCng(KeySize))
                    {

                        ECD.KeyDerivationFunction = ECDHKDF;
                        ECD.HashAlgorithm = HashingAlgorithm;

                        ECD.ImportECPrivateKey(PrivateKey, out _);

                        PublicKey = ECD.PublicKey.ToByteArray();

                        CngKey bobsKey = CngKey.Import(KeyToDeriveFrom, KeyBlobFormat);

                        PrivateKey = ECD.DeriveKeyMaterial(bobsKey);
                    }
                    return true;
                }
                catch (CryptographicException e)
                {
                    logger?.LogError("Failed to create shared secret for key pair {Error}", e);
                    return false;
                }
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        public bool TryDeriveKey<T>(byte[] PrivateKey, byte[] KeyToDeriveFrom, out byte[] DerivedPrivateKey, ILogger<T> logger)
        {
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    using (ECDiffieHellmanCng ECD = new ECDiffieHellmanCng(KeySize))
                    {

                        ECD.KeyDerivationFunction = ECDHKDF;
                        ECD.HashAlgorithm = HashingAlgorithm;

                        ECD.ImportECPrivateKey(PrivateKey, out _);

                        CngKey bobsKey = CngKey.Import(KeyToDeriveFrom, KeyBlobFormat);

                        DerivedPrivateKey = ECD.DeriveKeyMaterial(bobsKey);
                    }
                    return true;
                }
                catch (CryptographicException e)
                {
                    logger?.LogError("Failed to create shared secret for key pair {Error}", e);

                    DerivedPrivateKey = default;

                    return false;
                }
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        public bool TryGetPublicKey<T>(byte[] PrivateKey, out byte[] PublicKey, ILogger<T> logger)
        {
            if (OperatingSystem.IsWindows())
            {
                try
                {
                    using (ECDiffieHellmanCng ECD = new ECDiffieHellmanCng(KeySize))
                    {

                        ECD.KeyDerivationFunction = ECDHKDF;
                        ECD.HashAlgorithm = HashingAlgorithm;

                        ECD.ImportECPrivateKey(PrivateKey, out _);

                        PublicKey = ECD.PublicKey.ToByteArray();
                    }
                    return true;
                }
                catch (CryptographicException e)
                {
                    logger?.LogError("Failed to get public key with private key {Error}", e);

                    PublicKey = default;

                    return false;
                }
            }
            else
            {
                throw new NotSupportedException();
            }
        }
    }
}
