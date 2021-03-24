namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Represents a Diffie Hellman function that can be ratcheted one-way to create derivative keys that reset the KDF's of the symmetric functions.
    /// </summary>
    public interface IDiffieHellmanRatchet
    {
        /// <summary>
        /// The signature that proves the authenticity of the public key of this object
        /// </summary>
        byte[] IdentitySignature { get; }

        /// <summary>
        /// The private key of the DiffieHellman
        /// </summary>
        byte[] PrivateKey { get; }

        /// <summary>
        /// The public key of this diffiehellman
        /// </summary>
        byte[] PublicKey { get; }

        /// <summary>
        /// The X509IdentityKey of this object, this does not change and can be used to verify the authenticity of the key of this object
        /// </summary>
        byte[] X509IdentityKey { get; }

        void ImportState(string DiffieHellmanRatchetState);

        string ExportState();

        /// <summary>
        /// Generates the starting keys for this object. This function will reset the state of this object to the very beginning and a new secret must be created weith the other party. Provide identity keys to override the randomly generated ones. Identity keys are solely used for signing of keys and data
        /// </summary>
        void GenerateBaseKeys(byte[] X509IdentityKey = null, byte[] X509IdentityPrivateKey = null);

        /// <summary>
        /// Attempts to extract the public key from a private key.
        /// </summary>
        /// <param name="PrivateKey"></param>
        /// <param name="PublicKey"></param>
        /// <returns></returns>
        bool TryConvertPrivateKey(byte[] PrivateKey, out byte[] PublicKey);

        /// <summary>
        /// Attempts to create a shared secret between this object and another object. This object's private key will be replaced with the shared secret and the other obect will need to use our bundle to create their shared secret as well.
        /// </summary>
        /// <param name="X509IdentityKey"></param>
        /// <param name="PublicKey"></param>
        /// <param name="Signature"></param>
        /// <returns></returns>
        bool TryCreateSharedSecret(byte[] X509IdentityKey, byte[] PublicKey, byte[] Signature);

        /// <summary>
        /// Attempts to ratchet the diffie hellman forward by deriving another private key. This is a one-way function and past keys will be lost
        /// </summary>
        /// <param name="NewPrivateKey"></param>
        /// <returns></returns>
        bool TryRatchet(out byte[] NewPrivateKey);

        /// <summary>
        /// Attempts to verify the authenticity of the <paramref name="KeyToVerify"/> using the provided <paramref name="Signature"/> and <paramref name="X509IdentityKey"/>.
        /// </summary>
        /// <param name="KeyToVerify"></param>
        /// <param name="Signature"></param>
        /// <param name="X509IdentityKey"></param>
        /// <returns></returns>
        bool TryVerifyKey(byte[] KeyToVerify, byte[] Signature, byte[] X509IdentityKey);

        /// <summary>
        /// Attempts to sign the key using this object's private X509IdentityKey
        /// </summary>
        /// <param name="KeyToSign"></param>
        /// <param name="Signature"></param>
        /// <returns></returns>
        bool TrySignKey(byte[] KeyToSign, out byte[] Signature);

        /// <summary>
        /// Attempts to sign the key using  the provided private key
        /// </summary>
        /// <param name="KeyToSign"></param>
        /// <param name="Signature"></param>
        /// <returns></returns>
        bool TrySignKey(byte[] KeyToSign, byte[] PrivateKey, out byte[] Signature);
    }
}