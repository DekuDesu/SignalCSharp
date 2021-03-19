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
    // this disables the OS Warning
#pragma warning disable CA1416
    public class SignatureHandler : ISignatureHandler
    {
        private readonly ILogger<SignatureHandler> logger;

        public int KeySize { get; set; } = 256;

        public CngAlgorithm HashAlgorithm { get; set; } = CngAlgorithm.Sha256;

        public SignatureHandler(ILogger<SignatureHandler> _logger)
        {
            logger = _logger;
        }

        public bool TrySign(byte[] DataToSign, byte[] KeyToSignWith, out byte[] Signature, out byte[] x509PublicKey)
        {
            if (DataToSign?.Length is null or 0)
            {
                logger.LogError("{ParamName} provided to {MethodName} is null or emtpy.", nameof(DataToSign), nameof(TrySign));

                x509PublicKey = default;
                Signature = default;
                return false;
            }
            if (KeyToSignWith?.Length is null or 0)
            {
                logger.LogError("{ParamName} provided to {MethodName} is null or emtpy.", nameof(KeyToSignWith), nameof(TrySign));

                x509PublicKey = default;
                Signature = default;
                return false;
            }

            try
            {
                using ECDsaCng signer = new(KeySize);

                signer.HashAlgorithm = CngAlgorithm.Sha256;

                signer.ImportECPrivateKey(KeyToSignWith, out _);

                Signature = signer.SignData(DataToSign);

                x509PublicKey = signer.ExportSubjectPublicKeyInfo();

                return signer.VerifyData(DataToSign, Signature);
            }
            catch (CryptographicException e)
            {
                logger.LogError("Failed to sign data, {Error}", e);

                x509PublicKey = default;
                Signature = default;
                return false;
            }
        }

        public bool Verify(byte[] SignedData, byte[] Signature, byte[] X509PublicKey)
        {
            if (SignedData?.Length is null or 0)
            {
                logger.LogError("{ParamName} provided to {MethodName} is null or emtpy.", nameof(SignedData), nameof(Verify));

                return false;
            }
            if (Signature?.Length is null or 0)
            {
                logger.LogError("{ParamName} provided to {MethodName} is null or emtpy.", nameof(Signature), nameof(Verify));

                return false;
            }



            try
            {
                using ECDsaCng Signer = new(KeySize);

                Signer.ImportSubjectPublicKeyInfo(X509PublicKey, out _);

                Signer.HashAlgorithm = HashAlgorithm;

                return Signer.VerifyData(SignedData, Signature);
            }
            catch (CryptographicException e)
            {
                logger.LogError("Failed to verify signed data {Error,}", e);
                return false;
            }
        }
    }
}
