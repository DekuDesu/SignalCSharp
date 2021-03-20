namespace DingoAuthentication.Encryption
{
    public interface IDiffieHellmanRatchet
    {
        byte[] IdentitySignature { get; }
        byte[] PrivateKey { get; }
        byte[] PublicKey { get; }
        byte[] X509IndentityKey { get; }

        void GenerateBaseKeys();
        bool TryConvertPrivateKey(byte[] PrivateKey, out byte[] PublicKey);
        bool TryCreateSharedSecret(byte[] X509IdentityKey, byte[] PublicKey, byte[] Signature);
        bool TryRatchet(out byte[] NewPrivateKey);
        bool TryVerifyKey(byte[] KeyToVerify, byte[] Signature, byte[] X509IdentityKey);
        bool TrySignKey(byte[] KeyToSign, out byte[] Signature);
    }
}