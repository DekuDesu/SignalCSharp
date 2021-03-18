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
        public int RatchetLink { get; init; }
    }
}
