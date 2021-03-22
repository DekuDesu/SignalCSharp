namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Represents the Key Derivation Function ratchet that generates asymmetric encryption keys using the provided private key from a diffie hellman ratchet
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IKeyDerivationRatchet<T> where T : IEncryptedDataModel, new()
    {
        void ImportState(string KeyDerivationRatchetState);
        string ExportState();

        /// <summary>
        /// Resets the state of this object and re-seeds the private key using the provided key to make further derivations from.
        /// </summary>
        /// <param name="NewParentKey"></param>
        void Reset(byte[] NewParentKey);

        /// <summary>
        /// Derives the next key
        /// </summary>
        /// <param name="GeneratedKey"></param>
        /// <returns></returns>
        bool GenerateNextKey(out byte[] GeneratedKey);

        /// <summary>
        /// Attempts to decrypt the given data and outputs the DecryptedString if it was successfull
        /// </summary>
        /// <param name="DataToDecrypt"></param>
        /// <param name="DecryptedString"></param>
        /// <returns></returns>
        bool TryDecrypt(T DataToDecrypt, out string DecryptedString);

        /// <summary>
        /// Attempts to encrypt the given string and outpyts the encrypted data if it was successfull
        /// </summary>
        /// <param name="DataToEncrypt"></param>
        /// <param name="EncryptedData"></param>
        /// <returns></returns>
        bool TryEncrypt(ref string DataToEncrypt, out T EncryptedData);
    }
}