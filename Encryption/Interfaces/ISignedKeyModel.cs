namespace DingoAuthentication.Encryption
{
    public interface ISignedKeyModel
    {
        byte[] PublicKey { get; init; }
        byte[] Signature { get; init; }
    }
}