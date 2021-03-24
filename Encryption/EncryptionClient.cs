using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

[assembly: InternalsVisibleTo("DingoAuthentication.Tests")]

namespace DingoAuthentication.Encryption
{

    public class EncryptionClient<EncryptedDataModelType, KeyBundleModelType, SignedKeyModelType> : IEncryptionClient<EncryptedDataModelType>
        where EncryptedDataModelType : IEncryptedDataModel, new()
        where KeyBundleModelType : IKeyBundleModel, new()
        where SignedKeyModelType : ISignedKeyModel, new()
    {
        internal readonly ILogger<EncryptionClient<EncryptedDataModelType, KeyBundleModelType, SignedKeyModelType>> logger;

        /// <summary>
        /// Generates keys that seed the key derivation functions
        /// </summary>
        internal IDiffieHellmanRatchet dhRatchet;

        /// <summary>
        /// Generates keys that encrypt outgoin messages
        /// </summary>
        internal IKeyDerivationRatchet<EncryptedDataModelType> senderKDF;

        /// <summary>
        /// Generates keys that decrypt incoming messages
        /// </summary>
        internal IKeyDerivationRatchet<EncryptedDataModelType> receiverKDF;

        public EncryptionClient(
            ILogger<EncryptionClient<EncryptedDataModelType, KeyBundleModelType, SignedKeyModelType>> _logger,
            IDiffieHellmanRatchet _dhRatchet,
            IKeyDerivationRatchet<EncryptedDataModelType> _senderKDF,
            IKeyDerivationRatchet<EncryptedDataModelType> _receiverKDF
            )
        {
            logger = _logger;
            dhRatchet = _dhRatchet;
            senderKDF = _senderKDF;
            receiverKDF = _receiverKDF;
        }

        public string ExportState()
        {
            string[] state = new string[3];

            state[0] = dhRatchet.ExportState();

            state[1] = senderKDF.ExportState();

            state[2] = receiverKDF.ExportState();

            return Newtonsoft.Json.JsonConvert.SerializeObject(state);
        }

        public void ImportState(string EncryptionClientState)
        {
            string[] state = Newtonsoft.Json.JsonConvert.DeserializeObject<string[]>(EncryptionClientState);

            dhRatchet.ImportState(state[0]);

            senderKDF.ImportState(state[1]);

            receiverKDF.ImportState(state[2]);
        }

        public IKeyBundleModel GenerateBundle(byte[] X509IdentityKey = null, byte[] X509PrivateIdentityKey = null)
        {
            dhRatchet.GenerateBaseKeys(X509IdentityKey, X509PrivateIdentityKey);

            SignedKeyModelType PublicKey = new()
            {
                PublicKey = dhRatchet.PublicKey,
                Signature = dhRatchet.IdentitySignature
            };

            return new KeyBundleModelType()
            {
                X509IdentityKey = dhRatchet.X509IdentityKey,
                PublicKey = PublicKey
            };
        }

        public bool CreateSecretUsingBundle(IKeyBundleModel OtherClientBundle)
        {
            // we want to create a shared secret between us and another client so we can send messages back and fourth
            // make sure the bundle that we got contains ONLY keys from the identity key inside the bundle
            if (VerifySignedKey(OtherClientBundle.PublicKey, OtherClientBundle.X509IdentityKey) is false)
            {
                bool clientNull = (OtherClientBundle is null);
                logger.LogWarning("Failed to verify bundle provided Null?:{BudleIsNull} Possible MIM attack:{BundleFailedSigning}", clientNull, !clientNull);
                return false;
            }

            if (dhRatchet.TryCreateSharedSecret
                    (
                        OtherClientBundle.X509IdentityKey,
                        OtherClientBundle.PublicKey.PublicKey,
                        OtherClientBundle.PublicKey.Signature
                    )
                )
            {
                // make sure to set the seed key for the ratchets or else we wont be able to send or receive any messages
                senderKDF.Reset(dhRatchet.PrivateKey);

                receiverKDF.Reset(dhRatchet.PrivateKey);

                return true;
            }

            return false;
        }

        /// <summary>
        /// Attempts to encrypt the string using the sender ratchet.
        /// </summary>
        /// <returns>
        /// <see langword="true"/> The encryption was sucessfull
        /// <para>
        /// <see langword="false"/> The encryption failed, or a cryptographic exception was encountered.
        /// </para>
        /// </returns>
        public bool TryEncrypt(string DataToEncrypt, out EncryptedDataModelType EncryptedData)
        {
            bool pass = senderKDF.TryEncrypt(ref DataToEncrypt, out EncryptedData);

            if (pass)
            {
                if (dhRatchet.TrySignKey(EncryptedData.Data, out var Signature))
                {
                    EncryptedData.Signature = Signature;
                }
            }

            return pass;
        }

        /// <summary>
        /// Decrypts the provided encrypted data using the receiver ratchet
        /// </summary>
        /// <param name="EncryptedData"></param>
        /// <param name="DecryptedString"></param>
        /// <returns>
        /// <see langword="true"/> The decryption was sucessfull
        /// <para>
        /// <see langword="false"/> The decryption failed, or a cryptographic exception was encountered.
        /// </para>
        /// </returns>
        public bool TryDecrypt(EncryptedDataModelType EncryptedData, out string DecryptedString)
        {
            return receiverKDF.TryDecrypt(EncryptedData, out DecryptedString);
        }

        private bool VerifySignedKey(ISignedKeyModel SignedKey, byte[] X509IdentityKey)
        {
            return dhRatchet.TryVerifyKey(SignedKey.PublicKey, SignedKey.Signature, X509IdentityKey);
        }

        public void RatchetDiffieHellman()
        {
            if (dhRatchet.TryRatchet(out byte[] NewPrivateKey))
            {
                senderKDF.Reset(NewPrivateKey);
                receiverKDF.Reset(NewPrivateKey);
            }
        }

    }
}
