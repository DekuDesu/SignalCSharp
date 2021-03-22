namespace DingoAuthentication.Encryption
{
    public interface IEncryptionClient<EncryptedDataModelType> where EncryptedDataModelType : IEncryptedDataModel, new()
    {
        string ExportState();
        void ImportState(string EncryptionClientState);

        bool CreateSecretUsingBundle(IKeyBundleModel OtherClientBundle);
        IKeyBundleModel GenerateBundle();
        void RatchetDiffieHellman();
        bool TryDecrypt(EncryptedDataModelType EncryptedData, out string DecryptedString);
        bool TryEncrypt(string DataToEncrypt, out EncryptedDataModelType EncryptedData);
    }
}