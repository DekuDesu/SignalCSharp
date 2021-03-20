namespace DingoAuthentication.Encryption
{
    public interface IKeyBundleModel
    {
        ISignedKeyModel PublicKey { get; init; }
        byte[] X509IdentityKey { get; init; }
    }
}