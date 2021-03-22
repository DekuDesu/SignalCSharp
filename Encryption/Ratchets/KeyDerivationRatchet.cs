using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{
    public class KeyDerivationRatchet<T> : IKeyDerivationRatchet<T> where T : IEncryptedDataModel, new()
    {
        private readonly ILogger<KeyDerivationRatchet<T>> logger;
        private readonly IKeyDerivationFunction kdf;
        private readonly ISymmetricHandler<T> symmetricHandler;

        public byte[] ParentKey;

        public int CurrentLink = 0;

        private bool? SenderRatchet = null;

        private List<(int Link, byte[] Key)> StoredKeys = new();

        public KeyDerivationRatchet(ILogger<KeyDerivationRatchet<T>> _logger, IKeyDerivationFunction _KDF, ISymmetricHandler<T> _symmetricHandler)
        {
            logger = _logger;
            kdf = _KDF;
            symmetricHandler = _symmetricHandler;
        }

        public void ImportState(string KeyDerivationRatchetState)
        {
            KeyDerivationState state = Newtonsoft.Json.JsonConvert.DeserializeObject<KeyDerivationState>(KeyDerivationRatchetState);

            this.ParentKey = state.ParentKey;
            this.CurrentLink = state.CurrentLink;
            this.StoredKeys = state.StoredKeys;
            this.SenderRatchet = state.SenderRatchet;
        }

        public string ExportState()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(new KeyDerivationState()
            {
                ParentKey = this.ParentKey,
                CurrentLink = this.CurrentLink,
                StoredKeys = this.StoredKeys,
                SenderRatchet = this.SenderRatchet
            });
        }

        private class KeyDerivationState
        {
            public byte[] ParentKey { get; set; }
            public int CurrentLink { get; set; }
            public bool? SenderRatchet { get; set; }
            public List<(int Link, byte[] Key)> StoredKeys { get; set; }
        }

        public void Reset(byte[] NewParentKey)
        {
            ParentKey = NewParentKey;
            CurrentLink = 0;
        }

        public bool GenerateNextKey(out byte[] GeneratedKey)
        {
            if (ParentKey?.Length is null or 0)
            {
                logger.LogWarning("There is no {PropertyName} to which to generate a child key from. Ensure the {PropertyName} is set with a valid key", nameof(ParentKey), nameof(ParentKey));
                GeneratedKey = null;
                return false;
            }
            try
            {
                byte[] result = kdf.DeriveKey(ParentKey);

                CurrentLink++;

                GeneratedKey = result;

                return true;
            }
            catch (CryptographicException e)
            {
                logger.LogWarning("{Error}", e);
                GeneratedKey = null;
                return false;
            }
        }

        public bool TryEncrypt(ref string DataToEncrypt, out T EncryptedData)
        {
            if (SenderRatchet is false)
            {
                logger.LogError("Attempted to encrypt data with a Receiver HKDF Ratchet, a HKDF Ratchet can only be used EITHER for sending or receiving. The type of HKDF Ratchet is determined by whichever is used first, TryEncrypt(Sender) or TryDecrypt(Reciver).");
                EncryptedData = default;
                return false;
            }

            // since this is a sender the keys used should be private keys, private keys are 32 bytes
            kdf.KeySize = 256;
            SenderRatchet = true;

            // if we were successful in ratcheting one link
            if (GenerateNextKey(out ParentKey))
            {
                // try to encrypt the data
                bool pass = symmetricHandler.TryEncrypt(DataToEncrypt, ParentKey, out EncryptedData);

                if (pass)
                {
                    EncryptedData.RatchetLink = CurrentLink;
                }

                return pass;
            }
            else
            {
                EncryptedData = default;
                return false;
            }
        }

        public bool TryDecrypt(T DataToDecrypt, out string DecryptedString)
        {
            if (SenderRatchet is true)
            {
                logger.LogError("Attempted to decrypt data with a sender HKDF Ratchet, a HKDF Ratchet can only be used EITHER for sending or receiving. The type of HKDF Ratchet is determined by whichever is used first, TryEncrypt(Sender) or TryDecrypt(Reciver).");

                DecryptedString = default;
                return false;
            }

            SenderRatchet = false;

            // if the ratchet number given is larger than we expect, catch up to the ratchet number and store the keys
            if (DataToDecrypt.RatchetLink - CurrentLink > 1)
            {
                for (int i = 0; i < DataToDecrypt.RatchetLink - CurrentLink - 1; i++)
                {
                    if (GenerateNextKey(out ParentKey))
                    {
                        StoredKeys.Add((CurrentLink, ParentKey));
                    }
                }
            }

            // if the ratchet link provided is behind our current link it means its an old message
            if (DataToDecrypt.RatchetLink - CurrentLink < 0)
            {
                // check to see if we stored the key for later use
                (int Link, byte[] Key) found = StoredKeys.Where(x => x.Link == DataToDecrypt.RatchetLink).FirstOrDefault();

                if (found.Link != default && found.Key != default)
                {
                    // remove the used key
                    StoredKeys.Remove(found);

                    return symmetricHandler.TryDecrypt(DataToDecrypt, found.Key, out DecryptedString);
                }

                DecryptedString = null;
                return false;
            }
            else if (GenerateNextKey(out ParentKey))
            {
                // if we are neither behind or ahead of our expected ratchet position, ratchet once and decrypt
                // make sure we store the key if for some reason encryption failed
                if (symmetricHandler.TryDecrypt(DataToDecrypt, ParentKey, out DecryptedString))
                {
                    return true;
                }
                else
                {
                    // store the key to avoid Key Depletion Attacks
                    // this is to prevent an attacker from continuously requesting client decryption
                    StoredKeys.Add((CurrentLink, ParentKey));

                    return false;
                }
            }
            else
            {
                logger.LogError("Failed to generate next HKDF key.");

                DecryptedString = null;
                return false;
            }
        }

    }
}
