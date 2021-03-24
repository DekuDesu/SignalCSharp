namespace DingoAuthentication.Encryption
{
    public interface IEncryptionClient<EncryptedDataModelType> where EncryptedDataModelType : IEncryptedDataModel, new()
    {
        string ExportState();

        void ImportState(string EncryptionClientState);

        bool CreateSecretUsingBundle(IKeyBundleModel OtherClientBundle);

        IKeyBundleModel GenerateBundle(byte[] X509IdentityKey = null, byte[] X509PrivateIdentityKey = null);

        void RatchetDiffieHellman();

        bool TryDecrypt(EncryptedDataModelType EncryptedData, out string DecryptedString);

        bool TryEncrypt(string DataToEncrypt, out EncryptedDataModelType EncryptedData);
    }
}