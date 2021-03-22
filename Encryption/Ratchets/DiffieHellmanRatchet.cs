using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{
    public class DiffieHellmanRatchet : IDiffieHellmanRatchet
    {
        private readonly ILogger<DiffieHellmanRatchet> logger;
        private readonly IDiffieHellmanHandler dHH;
        private readonly IKeyDerivationFunction kdf;
        private readonly ISignatureHandler signer;

        // this should never be changed outside of constructor
        internal byte[] x509IdentityKey;
        // this should never be changed outside of constructor
        internal byte[] x509IdentityPrivateKey;

        private byte[] publicKey;
        private byte[] privateKey;

        private byte[] identitySignature;

        public byte[] PublicKey => publicKey;

        public byte[] PrivateKey => privateKey;

        public byte[] X509IdentityKey => x509IdentityKey;

        public byte[] IdentitySignature => identitySignature;

        public DiffieHellmanRatchet(ILogger<DiffieHellmanRatchet> _logger, IDiffieHellmanHandler _DHH, IKeyDerivationFunction _kdf, ISignatureHandler _signer)
        {
            logger = _logger;
            dHH = _DHH;
            kdf = _kdf;
            signer = _signer;
            logger = _logger;

            // create identity key
            (x509IdentityKey, x509IdentityPrivateKey) = dHH.GenerateKeys();

            // create starting keys
            (publicKey, privateKey) = dHH.GenerateKeys();

            // sign the identity key
            SignPublicKey();
        }

        public void ImportState(string DiffieHellmanRatchetState)
        {
            byte[][] state = Newtonsoft.Json.JsonConvert.DeserializeObject<byte[][]>(DiffieHellmanRatchetState);

            if (state?.Length is null or not 4)
            {
                logger.LogError("Failed to import state for DiffieHellmanRatchet State Given {State}", DiffieHellmanRatchetState);
                return;
            }

            this.x509IdentityKey = state[0];

            this.x509IdentityPrivateKey = state[1];

            this.publicKey = state[2];

            this.privateKey = state[3];

            SignPublicKey();
        }

        public string ExportState()
        {
            byte[][] data = new byte[4][];

            data[0] = x509IdentityKey;

            data[1] = x509IdentityPrivateKey;

            data[2] = publicKey;

            data[3] = privateKey;

            return Newtonsoft.Json.JsonConvert.SerializeObject(data);
        }

        public void GenerateBaseKeys()
        {
            (publicKey, privateKey) = dHH.GenerateKeys();

            // since we regenerated our keys we should re-sign them
            SignPublicKey();
        }

        public bool TryCreateSharedSecret(byte[] X509IdentityKey, byte[] PublicKey, byte[] Signature)
        {
            // make sure the  key we are using is actually signed by the private key of the identity of the person we are talking to
            if (signer.Verify(PublicKey, Signature, X509IdentityKey))
            {
                return dHH.TryCreateSharedSecret(ref publicKey, ref privateKey, PublicKey, logger);
            }
            return false;
        }

        public bool TryConvertPrivateKey(byte[] PrivateKey, out byte[] PublicKey)
        {
            return dHH.TryGetPublicKey(PrivateKey, out PublicKey, logger);
        }

        private bool TrySignPublicKey()
        {
            return signer.TrySign(publicKey, x509IdentityPrivateKey, out identitySignature, out x509IdentityKey);
        }

        public bool TrySignKey(byte[] KeyToSign, out byte[] Signature)
        {
            return signer.TrySign(KeyToSign, x509IdentityPrivateKey, out Signature, out x509IdentityKey);
        }

        public bool TrySignKey(byte[] KeyToSign, byte[] PrivateKey, out byte[] Signature)
        {
            return signer.TrySign(KeyToSign, PrivateKey, out Signature, out _);
        }


        public bool TryVerifyKey(byte[] KeyToVerify, byte[] Signature, byte[] X509IdentityKey)
        {
            return signer.Verify(KeyToVerify, Signature, X509IdentityKey);
        }

        private void SignPublicKey()
        {
            if (TrySignPublicKey() is false)
            {
                logger.LogError("Failed to sign identity key.");
            }
        }

        public bool TryRatchet(out byte[] NewPrivateKey)
        {
            try
            {
                privateKey = kdf.DeriveKey(privateKey);
                NewPrivateKey = PrivateKey;
                return true;
            }
            catch (CryptographicException e)
            {
                logger.LogError("Failed to ratchet DiffieHellman, {Error}", e);
                NewPrivateKey = default;
                return false;
            }
        }

    }
}
