namespace DingoAuthentication.Encryption
{
    public interface IDiffieHellmanRatchet
    {
        bool CreateSharedSecret(byte[] OtherPublicKey);
        void Reset();
    }
}