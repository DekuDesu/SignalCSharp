using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{
    public class KeyDerivationFunction : IKeyDerivationFunction
    {
        public byte[] Salt { get; set; } = { 168, 244, 151, 155, 119, 227, 249, 63 };

        public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

        /// <summary>
        /// The key size that should be generated in bits
        /// </summary>
        public int KeySize { get; set; } = 256;

        public byte[] DeriveKey(byte[] KeyToDeriveFrom)
        {
            byte[] key = HKDF.DeriveKey(HashAlgorithm, KeyToDeriveFrom, KeySize >> 3, Salt);

            return key;
        }
    }
}
