using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Certificates;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using System.Threading.Tasks;
using System;
using System.Threading;

namespace X509.Security
{
    /// <summary>
    /// Secret Management Function Class
    /// </summary>
    public static class SecretManager
    {

        /// <summary>
        /// Will retrieve and export a SecretManager PFX from an Azure Key Vault
        /// </summary>
        /// <param name="connectionCredential">The TokenCredential to use when connecting to the Key Vault.</param>
        /// <param name="certificateNameToDownload">The certificate name to download</param>
        /// <param name="keyVaultUri">The Key Vault URI</param>
        /// <param name="storageFlags">The storage flags to be used on the certificate when accessing the SecretManager from Azure. The default is Exportable.</param>
        /// <param name="certificateVersion">The version of the SecretManager if needed. The default will be the latest version.</param>
        /// <returns>Base 64 string version of the Certifcates Pfx</returns>
        /// <exception cref="NullReferenceException">Exception is raised if a Pfx can't be exported due to a missing Private Key in the SecretManager Download.</exception>
        public static Task<string> GetPfxAsBase64
        (
              TokenCredential connectionCredential
            , string certificateNameToDownload
            , Uri keyVaultUri
            , X509KeyStorageFlags storageFlags = X509KeyStorageFlags.Exportable
            , string certificateVersion = ""
        )
        {
            //default the return value
            Task<string> returnValue = Task.FromResult("");
           
            //create the certificate options for the certificate download
            DownloadCertificateOptions co = new DownloadCertificateOptions(certificateNameToDownload);
            co.KeyStorageFlags = storageFlags;
            if(!string.IsNullOrEmpty(certificateVersion)) co.Version = certificateVersion;

            var client = new CertificateClient(keyVaultUri, connectionCredential);
            var certificate = client.DownloadCertificate(co);

            //if the certificate has a private key then export it, otherwise raise an exception that can be logged.
            if(certificate.Value.HasPrivateKey)
            {
                byte[] pfx = certificate.Value.Export(X509ContentType.Pfx);
                returnValue = Task.FromResult(Convert.ToBase64String(pfx));
            }
            else
            {   //throw a null reference exception if the PFX can't be exported.
                throw new NullReferenceException("Missing Private Key value. The Pfx cannot be exported.");
            }
            return returnValue;
        }

        /// <summary>
        /// This Updates or Creates the specified KeyVault Secret
        /// </summary>
        /// <param name="connectionCredential">The TokenCredential to use when connecting to the Key Vault.</param>
        /// <param name="keyVaultSecret">The secret to be Updated or Created</param>
        /// <param name="keyVaultUri">The Key Vault URI</param>
        /// <param name="cancellationToken">The cancellation token required by the SetSecret call.</param>
        /// <returns></returns>
        public static Task<KeyVaultSecret> UpdateOrCreateKeyVaultSecret
        (
              TokenCredential connectionCredential
            , KeyVaultSecret keyVaultSecret
            , Uri keyVaultUri
            , CancellationToken cancellationToken
        )
        {

            //The set operation adds a secret to the Azure Key Vault. If the named secret already exists, Azure Key Vault creates a new version of that secret. This operation requires the secrets/set permission.
            SecretClient client = new SecretClient(keyVaultUri, connectionCredential);
            
            //Set the Secret 
            KeyVaultSecret returnSecret = client.SetSecret(keyVaultSecret, cancellationToken);

            return Task.FromResult(returnSecret);
        }


    }
}
