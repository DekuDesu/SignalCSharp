using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Defines the Cryptographic primitive requruirements of a KeyDerivationFunction
    /// </summary>
    public interface IKeyDerivationFunction
    {
        /// <summary>
        /// The salt that should be used by the KDF, this should be a cryptographicaly public constant
        /// </summary>
        byte[] Salt { get; set; }

        /// <summary>
        /// The hash algorithm used by the KDF
        /// </summary>
        HashAlgorithmName HashAlgorithm { get; set; }

        /// <summary>
        /// The size in bits that the hash algorithm should use to derive the next key.
        /// </summary>
        int KeySize { get; set; }

        /// <summary>
        /// Derives a new cryptographic key with the set bit size
        /// </summary>
        /// <param name="KeyToDeriveFrom"></param>
        /// <returns></returns>
        byte[] DeriveKey(byte[] KeyToDeriveFrom);
    }
}
