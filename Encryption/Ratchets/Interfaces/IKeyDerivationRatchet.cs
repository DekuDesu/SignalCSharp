namespace DingoAuthentication.Encryption
{
    public interface IKeyDerivationRatchet<T> where T : IEncryptedDataModel, new()
    {
        void Reset(byte[] NewParentKey);
        bool GenerateNextKey(out byte[] GeneratedKey);
        bool TryDecrypt(T DataToDecrypt, out string DecryptedString);
        bool TryEncrypt(ref string DataToEncrypt, out T EncryptedData);
    }
}