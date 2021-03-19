namespace DingoAuthentication.Encryption
{
    public interface IDiffieHellmanRatchet
    {
        byte[] IdentitySignature { get; }
        byte[] PrivateKey { get; }
        byte[] PublicKey { get; }
        byte[] X509IndentityKey { get; }

        void GenerateBaseKeys();
        bool TryCreateSharedSecret(byte[] X509IdentityKey, byte[] PublicKey, byte[] Signature);
        bool TryRatchet(out byte[] NewPrivateKey);
    }
}