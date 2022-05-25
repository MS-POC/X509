using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace X509.Security
{
    public static  class CertificateHelper
    {

        /// <summary>
        /// Finds the certificate by thumbprint.
        /// </summary>
        /// <param name="findValue">The find value.</param>
        /// <returns><see cref="X509Certificate2"/></returns>
        public static X509Certificate2 FindCertificate(string findValue, X509FindType findType)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                var col = store.Certificates.Find(
                    findType,
                    findValue,
                    false);

                return col.Count == 0 ? null : col[0];
            }
            finally
            {
                store.Close();
            }
        }




    }
}
