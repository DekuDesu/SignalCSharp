using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{
    /// <summary>
    /// Object representing symmetrically ecrypted data
    /// </summary>
    public class EncryptedDataModel : IEncryptedDataModel
    {
        /// <summary>
        /// The Symmetrically encrypted data
        /// </summary>
        public byte[] Data { get; init; }

        /// <summary>
        /// The IV used to encrypt the data
        /// </summary>
        public byte[] IV { get; init; }

        /// <summary>
        /// The ratchet link number that was used to generate this data, this is only used when a ratchet is used to encrypt this data otherise 0;
        /// </summary>
        public int RatchetLink { get; set; }

        /// <summary>
        /// The signature of the encrypted data using the X509IdentityKey of the party who encrypted the data
        /// </summary>
        public byte[] Signature { get; set; }
    }
}
