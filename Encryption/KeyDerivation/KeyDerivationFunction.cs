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

        public HashAlgorithmName HashAlgorithm { get; set; }

        public int KeySize { get; set; } = 256;

        public byte[] DeriveKey(byte[] KeyToDeriveFrom)
        {
            byte[] key = HKDF.DeriveKey(HashAlgorithm, KeyToDeriveFrom, 256, Salt);

            byte[] extract = HKDF.Extract(HashAlgorithm, key, Salt);

            return extract;
        }
    }
}
