using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace X509.Security
{
    public  class AutorotationOperations
    {

        /// <summary>
        /// Accepts the information in the parameters to take a source certificate from the source key vault, base64 the PFX of that certificate and then inserts updates the base64
        /// string of the certificate to the specified secret.
        /// 
        /// This method uses the integrated security operations of (DefaultAzureCredential) to connect and perform the operations.
        /// 
        /// </summary>
        /// <param name="sourceCertificateName">The Source Certificate Name as it is in the Keyvault</param>
        /// <param name="sourceCertificateKeyVaultUrlString">The KeyVault URL found on the Overview Page in Azure</param>
        /// <param name="targetSecretName">The Target Secret Name as it is to appear in the Keyvault secrets</param>
        /// <param name="targetSecretKeyVaultUrlString"></param>
        /// <see cref="https://docs.microsoft.com/en-us/dotnet/api/azure.identity?view=azure-dotnet"/>
        public static void Base64CertificateToSecret
        (
            string sourceCertificateName
          , string sourceCertificateKeyVaultUrlString
          , string targetSecretName
          , string targetSecretKeyVaultUrlString
        )
        {
    
            //step 1: Get the Default Credential used to connect to Azure
            var credential = new DefaultAzureCredential();

            //step 2: Source - call the static function to get the PFX as Base64 string
            Task<string> result = SecretManager.GetPfxAsBase64(credential, sourceCertificateName, new Uri(sourceCertificateKeyVaultUrlString));

            //step 3: Targe - Insert or update the KeyVault Secret where the base64 string is to be inserted
            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            CancellationToken cancellationToken = cancellationTokenSource.Token;

            KeyVaultSecret keyVaultSecret =
                new KeyVaultSecret(targetSecretName, result.Result);
            Task<KeyVaultSecret> keyVaultUpdate = SecretManager.UpdateOrCreateKeyVaultSecret(credential, keyVaultSecret, new Uri(targetSecretKeyVaultUrlString), cancellationToken);
        }

    }
}
