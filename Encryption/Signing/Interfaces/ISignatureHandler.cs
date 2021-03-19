using System.Security.Cryptography;

namespace DingoAuthentication.Encryption
{
    public interface ISignatureHandler
    {
        CngAlgorithm HashAlgorithm { get; set; }
        int KeySize { get; set; }

        bool TrySign(byte[] DataToSign, byte[] KeyToSignWith, out byte[] Signature, out byte[] X509PublicKey);
        bool Verify(byte[] SignedData, byte[] Signature, byte[] X509PublicKey);
    }
}