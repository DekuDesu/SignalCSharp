namespace DingoAuthentication.Encryption
{
    public interface IEncryptionClient<TEncryptedDataModelType, TSignedKeyModelType>
        where TEncryptedDataModelType : IEncryptedDataModel, new()
        where TSignedKeyModelType : ISignedKeyModel, new()
    {
        /// <summary>
        /// Returns true when this client has created a secret with another client
        /// </summary>
        bool CreatedSecret { get; }
        string ExportState();

        void ImportState(string EncryptionClientState);

        bool CreateSecretUsingBundle(IKeyBundleModel<TSignedKeyModelType> OtherClientBundle);

        IKeyBundleModel<TSignedKeyModelType> GenerateBundle(byte[] X509IdentityKey = null, byte[] X509PrivateIdentityKey = null);

        void RatchetDiffieHellman();

        bool TryDecrypt(TEncryptedDataModelType EncryptedData, out string DecryptedString);

        bool TryEncrypt(string DataToEncrypt, out TEncryptedDataModelType EncryptedData);
    }
}