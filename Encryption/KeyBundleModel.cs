using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Container for keys used for inital exhanges
    /// </summary>
    public class KeyBundleModel<T> : IKeyBundleModel<T> where T : ISignedKeyModel, new()
    {
        /// <summary>
        /// The identifying key that was used to sign all the keys in this object
        /// </summary>
        public byte[] X509IdentityKey { get; init; }

        /// <summary>
        /// The public key that should be used for initial Diffie Hellman Secret
        /// </summary>
        public T PublicKey { get; init; }
    }
}
