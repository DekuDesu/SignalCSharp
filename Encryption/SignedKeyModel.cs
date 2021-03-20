using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{
    public class SignedKeyModel : ISignedKeyModel
    {
        public byte[] PublicKey { get; init; }
        public byte[] Signature { get; init; }

        public SignedKeyModel(byte[] PublicKey, byte[] Signature)
        {
            this.PublicKey = PublicKey;
            this.Signature = Signature;
        }
        public SignedKeyModel()
        {

        }
    }
}
