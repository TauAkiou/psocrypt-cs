using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace PSOCrypt.Exceptions
{
    [Serializable]
    public class PSOEncryptionException : Exception
    {
        public PSOEncryptionException()
        {
        }

        public PSOEncryptionException(string message) : base(message)
        {
        }

        public PSOEncryptionException(string message, Exception inner)
    : base(message, inner)
        {
        }
    }
}
