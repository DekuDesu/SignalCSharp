namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Describes the data model that represents a Key bundle used for the initial creation of a secret between two parties
    /// </summary>
    public interface IKeyBundleModel
    {
        /// <summary>
        /// The signed public key of the other party.
        /// </summary>
        ISignedKeyModel PublicKey { get; init; }

        /// <summary>
        /// The identity key that was ideally used to sign the public key
        /// </summary>
        byte[] X509IdentityKey { get; init; }
    }
}