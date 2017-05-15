using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace PSOCrypt.Exceptions
{
    [Serializable]
    public class PSOCryptException : Exception
    {
        public PSOCryptException()
        {
        }

        public PSOCryptException(string message) : base(message)
        {
        }

        public PSOCryptException(string message, Exception inner)
    : base(message, inner)
        {
        }
    }
}
