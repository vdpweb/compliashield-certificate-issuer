
namespace CompliaShield.CertificateIssuer.ConsoleApp
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;

    public class CertificateStore
    {

        public X509Certificate2 GetCertificate(string thumbprint)
        {
 
            if(thumbprint == null || thumbprint.Length != 40)
            {
                throw new ArgumentException("Invalid thumbprint.");
            }

            Exception exception = null;
            X509Certificate2 cert = null;
            try
            {
                cert = this.GetCertificate(thumbprint, StoreLocation.CurrentUser);
                if(cert != null && cert.HasPrivateKey)
                {
                    return cert;
                }
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            try
            {
                var cert2 = this.GetCertificate(thumbprint, StoreLocation.LocalMachine);
                // most favorable pattern for having a private key
                if (cert2 != null && cert2.HasPrivateKey)
                {
                    return cert2;
                }
                else if(cert != null)
                {
                    return cert;
                }
                else if(cert2 != null)
                {
                    return cert2;
                }
            }
            catch (Exception ex)
            {
                if(exception != null)
                {
                    throw exception;
                }
                throw ex;
            }
            return null;
        }

        public X509Certificate2 GetCertificate(string thumbprint, StoreLocation storeLocation)
        {
            X509Store certStore = new X509Store(StoreName.My, storeLocation);
            X509Certificate2 certToUse = null;
            try
            {
                try
                {
                    certStore.Open(OpenFlags.ReadOnly);
                }
                catch (Exception ex)
                {
                    var outerEx = new Exception("Failed to open X509Store My on CurrentUser.", ex);
                    throw outerEx;
                }
                var primaryCertificateThumbprint = thumbprint.ToLower();

                var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, primaryCertificateThumbprint, false);
                if (certCollection == null || certCollection.Count == 0)
                {
                    return null;
                }
                certToUse = certCollection[0];
                if (certToUse.Thumbprint.ToLower() != primaryCertificateThumbprint.ToLower())
                {
                    return null;
                }
            }
            finally
            {
                certStore.Close();
            }
            return certToUse;
        }

    }
}
