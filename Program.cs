// See https://aka.ms/new-console-template for more information



using X509.Security;


//Certificate helper, finding a certificate by its subject name on your local computer
//var cert = Certificate.FindCertificate("", System.Security.Cryptography.X509Certificates.X509FindType.FindBySubjectName);

//Test call to move a certificate from a specified certificate store to a keyvault secret.
AutorotationOperations.Base64CertificateToSecret("[CertificateName]", "https://[keyvaultname].vault.azure.net/", "[SecretName]", "https://[keyvaultname].vault.azure.net/");

//Console.WriteLine(cert.FriendlyName);

