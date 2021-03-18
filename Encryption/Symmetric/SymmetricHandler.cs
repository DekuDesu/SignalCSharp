using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{

    public class SymmetricHandler<T> : ISymmetricHandler<T> where T : IEncryptedDataModel, new()
    {
        private readonly ILogger<SymmetricHandler<T>> logger;

        public int KeySize { get; set; } = 256;

        public SymmetricHandler(ILogger<SymmetricHandler<T>> _logger)
        {
            logger = _logger;
        }

        public bool TryEncrypt(string DataToEncrypt, byte[] Key, out T EncryptedData)
        {
            // Check arguments.
            if (string.IsNullOrEmpty(DataToEncrypt))
            {
                logger.LogError("Failed to {ClassName} {VarName}, {VarName} is null or 0, {OtherVarName} also null? ({KeyAlsoNull})", nameof(TryEncrypt), nameof(DataToEncrypt), nameof(DataToEncrypt), nameof(Key), Key is null);

                EncryptedData = default;
                return false;
            }

            if (Key?.Length is null or 0)
            {
                logger.LogError("Failed to {ClassName} {VarName}, {VarName} is null or 0, {OtherVarName} also null? ({KeyAlsoNull})", nameof(TryEncrypt), nameof(Key), nameof(Key), nameof(DataToEncrypt), Key is null);

                EncryptedData = default;
                return false;
            }

            // create arrays to store and finally assign into the encrupted T object at the end, the T object has init properties and can't be assigned after initial assignment
            byte[] encrypted;
            byte[] IV;

            try
            {
                using (AesCryptoServiceProvider symmetricProvider = new AesCryptoServiceProvider())
                {
                    // set the key size to the assigned value
                    symmetricProvider.KeySize = KeySize;

                    // assign the key we want to encrypt with
                    symmetricProvider.Key = Key;

                    // assign the given IV
                    IV = symmetricProvider.IV;

                    // Create an encryptor to perform the stream transform.
                    ICryptoTransform encryptor = symmetricProvider.CreateEncryptor(symmetricProvider.Key, symmetricProvider.IV);

                    // Create the streams used for encryption.
                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(DataToEncrypt);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }
            }
            catch (CryptographicException e)
            {
                logger.LogError("{ClassName} Error: {Error}", nameof(TryEncrypt), e);

                EncryptedData = default;
                return false;
            }

            EncryptedData = new T() { Data = encrypted, IV = IV };
            return true;
        }

        public bool TryDecrypt(T EncryptedData, byte[] Key, out string DecryptedString)
        {
            // Ensure we don't throw unexpected errors
            if (EncryptedData is null)
            {
                logger.LogError("Attempted to Decrypt null data Key: ({KeyExists})", Key is null);
                DecryptedString = null;
                return false;
            }

            if (EncryptedData.Data?.Length is null or 0)
            {
                logger.LogError("Failed to Decrypt using {VarName}, property was null, {OtherPropName} is null? (OtherPropIsNull)", nameof(EncryptedData), nameof(EncryptedData.Data), nameof(EncryptedData.IV), EncryptedData.IV is null);

                DecryptedString = null;
                return false;
            }

            if (EncryptedData.IV?.Length is null or 0)
            {
                logger.LogError("Failed to Decrypt using {VarName}, property was null, {OtherPropName} is null? (OtherPropIsNull)", nameof(EncryptedData), nameof(EncryptedData.IV), nameof(EncryptedData.Data), EncryptedData.Data is null);

                DecryptedString = null;
                return false;
            }

            if (Key?.Length is null or 0)
            {
                logger.LogError("Attempted to Decrypt data with null key Data: ({DataExists})", EncryptedData is null);
                DecryptedString = null;
                return false;
            }

            try
            {
                // Create an AesManaged object
                // with the specified key and IV.
                using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
                {
                    aesAlg.KeySize = KeySize;

                    aesAlg.Key = Key;

                    aesAlg.IV = EncryptedData.IV;

                    // Create a decryptor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for decryption.
                    using (MemoryStream msDecrypt = new MemoryStream(EncryptedData.Data))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {

                                // Read the decrypted bytes from the decrypting stream
                                // and place them in a string.
                                DecryptedString = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                return true;
            }
            catch (CryptographicException e)
            {
                logger.LogError("{ClassName} Error: {Error}", nameof(TryEncrypt), e);

                DecryptedString = default;
                return false;
            }
        }
    }
}
