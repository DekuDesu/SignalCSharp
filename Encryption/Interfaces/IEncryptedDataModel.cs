namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// The container that holds encrypted data after it's been encrupted by a symmetric primitive
    /// </summary>
    public interface IEncryptedDataModel
    {
        byte[] Data { get; init; }
        byte[] IV { get; init; }
        int RatchetLink { get; init; }
    }
}