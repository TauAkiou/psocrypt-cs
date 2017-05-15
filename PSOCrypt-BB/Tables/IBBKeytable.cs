using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PSOCrypt.Tables
{
    public interface IBBKeytable
    {
        uint[] Table { get; }
    }
}
