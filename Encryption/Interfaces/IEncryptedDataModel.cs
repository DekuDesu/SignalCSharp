namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Describes the data model that represents symmetrically encrypted information, the IV used to encrypt it, and the ratchet link it was assigned
    /// </summary>
    public interface IEncryptedDataModel
    {
        /// <summary>
        /// The symmetrically encrypted data
        /// </summary>
        byte[] Data { get; init; }

        /// <summary>
        /// The symmetric IV used to encrypt the data
        /// </summary>
        byte[] IV { get; init; }

        /// <summary>
        /// The ratchet link that was used to encrypt the data
        /// </summary>
        int RatchetLink { get; set; }

        /// <summary>
        /// The signature of the encrypted data using the X509IdentityKey of the party who encrypted the data
        /// </summary>
        public byte[] Signature { get; set; }
    }
}