namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Represents the data model that represents a Public key that has been signed, and the signature
    /// </summary>
    public interface ISignedKeyModel
    {
        /// <summary>
        /// The public key of the other party
        /// </summary>
        byte[] PublicKey { get; init; }

        /// <summary>
        /// The signature that proves the key was signed by the private X509IdentityKey of the other party.
        /// </summary>
        byte[] Signature { get; init; }
    }
}