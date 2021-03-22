namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Handles the symmetric encryption used for messages, this is by default AES
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface ISymmetricHandler<T> where T : IEncryptedDataModel, new()
    {
        /// <summary>
        /// Sets the key size in bits that the handler should use for encryption. Using the wrong key size will cause all Decryption and Encryption attempts to fail.
        /// </summary>
        int KeySize { get; set; }

        /// <summary>
        /// Attempts to Decrypt the given <see cref="T"/> <paramref name="EncryptedData"/>. 
        /// <para>
        /// This method should eat errors silently and use the returned bool as indication of failure or class implemented logger.
        /// </para>
        /// </summary>
        /// <param name="EncryptedData"></param>
        /// <param name="Key"></param>
        /// <param name="DecryptedString"></param>
        /// <returns>
        /// <see langword="true"/> when Decryption was successful and encountered no errors
        /// <para>
        /// <see langword="false"/> when Decryption failed, errors were encountered, or the inputs were invalid
        /// </para>
        /// </returns>
        bool TryDecrypt(IEncryptedDataModel EncryptedData, byte[] Key, out string DecryptedString);

        /// <summary>
        /// Attempts to Encrypt the given <see cref="T"/> <paramref name="EncryptedData"/>. 
        /// <para>
        /// This method should eat errors silently and use the returned bool as indication of failure or class implemented logger.
        /// </para>
        /// </summary>
        /// <param name="EncryptedData"></param>
        /// <param name="Key"></param>
        /// <param name="DecryptedString"></param>
        /// <returns>
        /// <see langword="true"/> when Encrypt was successful
        /// <para>
        /// <see langword="false"/> when Encrypt failed, errors were encountered, or the inputs were invalid
        /// </para>
        /// </returns>
        bool TryEncrypt(string DataToEncrypt, byte[] Key, out T EncryptedData);
    }
}