
namespace UnitTestProject1
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Cryptography;
    using Org.BouncyCastle.Crypto;
    using System.IO;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;

    public class Encryption
    {

        #region properties



        #endregion

        #region .ctors



        #endregion

        #region methods

        public byte[] Encrypt(byte[] certificate, object data)
        {
            var x509 = new X509Certificate2(certificate);
            byte[] plainTextBytes = Serializer.SerializeToByteArray(data);
            using (var cert = (RSACryptoServiceProvider)x509.PublicKey.Key)
            {
                return cert.Encrypt(plainTextBytes, true);
            }
        }

        public object Decrypt(byte[] certificate, string password, byte[] encryptedBytes)
        {
            byte[] decryptedBytes;

            // load the certificate and decrypt the specified data
            using (var ss = new System.Security.SecureString())
            {
                foreach (var keyChar in password.ToCharArray())
                    ss.AppendChar(keyChar);

                // load the password protected certificate file
                var cert = new X509Certificate2(certificate, ss);
                using (RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert.PrivateKey)
                {
                    decryptedBytes = rsa.Decrypt(encryptedBytes, true);
                }
            }

            object returnObj =  Serializer.DeserializeFromByteArray(decryptedBytes);
            return returnObj;
        }

        public object Decrypt(byte[] pem, byte[] encryptedBytes)
        {
            RsaPrivateCrtKeyParameters privateKey;
            var pemValue = System.Text.Encoding.Default.GetString(pem);

            var reader = new PemReader(new StringReader(pemValue));
            Object obj = reader.ReadObject();
            if (obj is AsymmetricCipherKeyPair)
            {
                privateKey = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)obj).Private;
            }
            else
            {
                throw new ArgumentException("'pem' value cannot translate to valid RsaPrivateCrtKeyParameters.");
            }
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(privateKey);
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider();
            rsaKey.ImportParameters(rsaParams);
            // decrypt the value
            var decryptedBytes = rsaKey.Decrypt(encryptedBytes, true);
            Serializer.DeserializeFromByteArray(decryptedBytes);
            return decryptedBytes;
        }


        #endregion

        #region helpers



        #endregion

    }
}
