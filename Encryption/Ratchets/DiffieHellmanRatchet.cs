using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DingoAuthentication.Encryption
{
    public class DiffieHellmanRatchet : IDiffieHellmanRatchet
    {
        private readonly ILogger<DiffieHellmanRatchet> logger;
        private readonly IDiffieHellmanHandler dHH;

        public byte[] PublicKey;

        public byte[] PrivateKey;

        public DiffieHellmanRatchet(ILogger<DiffieHellmanRatchet> _logger, IDiffieHellmanHandler _DHH)
        {
            logger = _logger;
            dHH = _DHH;
        }

        public DiffieHellmanRatchet(ILogger<DiffieHellmanRatchet> _logger)
        {
            logger = _logger;
            (PublicKey, PrivateKey) = dHH.GenerateKeys();
        }

        public void Reset()
        {
            (PublicKey, PrivateKey) = dHH.GenerateKeys();
        }

        public bool CreateSharedSecret(byte[] OtherPublicKey)
        {
            return dHH.TryCreateSharedSecret(ref PublicKey, ref PrivateKey, OtherPublicKey, logger);
        }
    }
}
