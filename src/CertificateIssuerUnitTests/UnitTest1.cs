


namespace CompliaShield.CertificateIssuerUnitTests
{
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Org.BouncyCastle.OpenSsl;
    using CompliaShield.CertificateIssuerUnitTests.Code;
    using System;

    [TestClass]
    public class UnitTest1
    {

        [TestClass]
        public class CertificateGeneratorTests
        {

            [TestMethod]
            public void TestDateStuff()
            {
                var certCreatedOn = DateTime.UtcNow;
                Console.WriteLine("utc ticks: " + certCreatedOn.Ticks.ToString());

                var now = DateTime.Now;
                Console.WriteLine("now ticks: " + now.Ticks.ToString());

                var diff = (now - certCreatedOn);
                Console.WriteLine("hours: " + (long)diff.TotalHours);

                Console.WriteLine("secs: " + (long)diff.TotalSeconds);

                TimeZone zone = TimeZone.CurrentTimeZone;
                // Demonstrate ToLocalTime and ToUniversalTime.
                DateTime local = zone.ToLocalTime(now);
                DateTime universal = zone.ToUniversalTime(now);
                Console.WriteLine("local: " + local);
                Console.WriteLine("universal: " + universal);

                var expirationAsString = "3/3/2017";
                //DateTime expire1;

                DateTime expirationDate;
                var isValid = TryGetexpireDate(expirationAsString, out expirationDate);
               
                //DateTime expirationDate = zone.ToUniversalTime(expire1);

                var secondsUntilExpires = (long)(expirationDate - certCreatedOn).TotalSeconds + 1;
                Console.WriteLine("secondsUntilExpires: " + secondsUntilExpires.ToString());

                var exp1 = now.AddSeconds(secondsUntilExpires);
                Console.WriteLine("exp1: " + exp1.ToString());

                //var secondsUntilExpires2 = (long)(expire1 - certCreatedOn).TotalSeconds + 1;
                //Console.WriteLine("secondsUntilExpires2: " + secondsUntilExpires2.ToString());

                //var exp2 = now.AddSeconds(secondsUntilExpires2);
                //Console.WriteLine("exp2: " + exp2.ToString());

                //var secondsUntilExpires = (long)(expirationDate - certCreatedOn).TotalSeconds + 1;
            }


            static bool TryGetexpireDate(string expirationAsString, out DateTime expireDate)
            {

                DateTime expire1;
                var isValid = DateTime.TryParse(expirationAsString, out expire1);

                TimeZone zone = TimeZone.CurrentTimeZone;
                expireDate = zone.ToUniversalTime(expire1);
                return true;
            }



            string _rootPassword = "dkn-2jnldUUien$3kde#2neo0-PPqRb";

            [TestMethod]
            public void GenerateRootCa()
            {
                var sn = "Test Root CA";
                string pemValue;
                var rootCa = CertificateGenerator.GenerateRootCertificate(sn, _rootPassword, out pemValue);
                var cert = new X509Certificate2(rootCa, _rootPassword);
                Assert.AreEqual("CN=" + sn, cert.Subject);
            }

            [TestMethod]
            public void GenerateCertificate_Test_ValidCertificate()
            {
                // Arrange
                string subjectName = "localhost";

                var root = System.IO.File.ReadAllBytes(@"C:\_rootCa.pfx");
                //var pemValue = System.IO.File.ReadAllText(@"C:\_rootCa.pem");

                // Act
                string password;
                byte[] actual = CertificateGenerator.GenerateCertificate(subjectName, root, _rootPassword, out password);

                // Assert
                var cert = new X509Certificate2(actual, password);
                Assert.AreEqual("CN=" + subjectName, cert.Subject);
                // Assert.IsInstanceOfType(cert.PrivateKey, typeof(RSACryptoServiceProvider));
            }

            [TestMethod]
            public void EncryptionTestCerts()
            {
                // Files already created and to be used

                // _Test_Encryption.cer
                // _Test_Encryption.pfx
                // _Test_Encryption_Password.txt

                var encryption = new Encryption();

                var toEncrypt = "Hello world!";

                //var toEncrypt = System.IO.File.ReadAllText(@"C:\_large_text.txt");

                //var toEncryptBytes = Encoding.UTF8.GetBytes(toEncrypt);

                var cert = System.IO.File.ReadAllBytes(@"C:\_Test_Encryption.cer");

                var encrypted = encryption.Encrypt(cert, toEncrypt);

                var pfx = System.IO.File.ReadAllBytes(@"C:\_Test_Encryption.pfx");
                var password = System.IO.File.ReadAllText(@"C:\_Test_Encryption_Password.txt");

                var decrypted = (string)encryption.Decrypt(pfx, password, encrypted);

                Assert.AreEqual(toEncrypt, decrypted);

            }

            [TestMethod]
            public void ParsePem()
            {
                var pemValue = System.IO.File.ReadAllText(@"C:\_rootCa.pem");
                var reader = new PemReader(new StringReader(pemValue));


                object obj;

                while ((obj = reader.ReadObject()) != null)
                {
                    var typeStr = obj.GetType().FullName;
                    System.Diagnostics.Debug.WriteLine(typeStr);
                    if (obj is Org.BouncyCastle.X509.X509Certificate)
                    {
                        var cert = (Org.BouncyCastle.X509.X509Certificate)obj;
                    }
                    else if (obj is Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)
                    {
                        var ackp = (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)obj;
                    }
                }








                //if (obj is AsymmetricCipherKeyPair)
                //{
                //    privateKey = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)obj).Private;
                //}
                //else
                //{s
                //    throw new InvalidOperationException("certificate did not have private key.");
                //}


                //                rivateKey key = null;
                //X509Certificate cert = null;
                //KeyPair keyPair = null;

                //final Reader reader = new StringReader(pem);
                //try {
                //    final PEMReader pemReader = new PEMReader(reader, new PasswordFinder() {
                //        @Override
                //        public char[] getPassword() {
                //            return password == null ? null : password.toCharArray();
                //        }
                //    });

                //    Object obj;
                //    while ((obj = pemReader.readObject()) != null) {
                //        if (obj instanceof X509Certificate) {
                //            cert = (X509Certificate) obj;
                //        } else if (obj instanceof PrivateKey) {
                //            key = (PrivateKey) obj;
                //        } else if (obj instanceof KeyPair) {
                //            keyPair = (KeyPair) obj;
                //        }
                //    }
                //} finally {
                //    reader.close();
                //}



            }

            //[TestMethod]
            //public void AlternatieSelfSignedAndRoot()
            //{
            //    var caPrivKey = Utility.GenerateCACertificate("CN=VDP Web 2");
            //    var cert = Utility.GenerateSelfSignedCertificate("CN=bitchpudding.com", "CN=VDP Web 2", caPrivKey);
            //    Utility.AddCertToStore(cert, StoreName.My, StoreLocation.CurrentUser);
            //}
        }
    }
}
