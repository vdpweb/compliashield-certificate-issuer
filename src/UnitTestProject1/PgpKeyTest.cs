
namespace UnitTestProject1
{
    using System;
    using System.Configuration;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Org.BouncyCastle.Crypto.Prng;

    [TestClass]
    public class PgpKeyTest
    {
        private readonly string _dummyIdentity = "Slim Shady <slimshady@compliashield.com>";
        private readonly string _dummyKeyPassword = "hello world!";

        private readonly string _basePath = @"C:\temp\pgp";

        [TestMethod]
        public void TestGenerateKey()
        {
            PgpKeyRingGenerator krgen = CreateKeyRingGenerator(_dummyIdentity, _dummyKeyPassword);

            // Generate public key ring, dump to file.
            PgpPublicKeyRing pkr = krgen.GeneratePublicKeyRing();
            BufferedStream pubout = new BufferedStream(new FileStream(@"c:\temp\pgp\dummy2.asc", System.IO.FileMode.Create));
            pkr.Encode(pubout);
            pubout.Close();

            // Generate private key, dump to file.
            PgpSecretKeyRing skr = krgen.GenerateSecretKeyRing();
            BufferedStream secout = new BufferedStream(new FileStream(@"c:\temp\pgp\dummyprivate2.asc", System.IO.FileMode.Create));
            skr.Encode(secout);
            secout.Close();

        }

        [TestMethod]
        public void TestEncrypt()
        {

            var publicKeyPath = _basePath + @"\dummy2.asc";

            var fi = new FileInfo(_basePath + @"\plain-text.txt");  //@"\_Deliverables.txt.gpg");
            CryptoHelper.EncryptPgpFile(fi.FullName, fi.FullName + ".gpg", publicKeyPath, true, true);
        }

        [TestMethod]
        public void TestSignAndEncrypt()
        {

            //var password = "panda4@panda.com";
            //var privateKeyPath = _basePath + @"\panda4_private.asc";
            //long privateSigningKeyId = 2771095709836830184;

            var privateKeyPath = _basePath + @"\johnfager_private.asc";
            var password = "}e&JduRAzKW89mfWBphF";
            //long privateSigningKeyId = -7083391141924604799;

            var fi = new FileInfo(_basePath + @"\NickNameTable.csv");
            var outputFileName = _basePath + @"\NickNameTable.csv.gpg";

            var publicKeyPath = _basePath + @"\panda3_public.asc";

            using (var publicKeyStream = File.OpenRead(publicKeyPath))
            {
                using (var privateKeyStream = File.OpenRead(privateKeyPath))
                {
                    try
                    {
                        using (var outputStream = File.Create(outputFileName))
                        {
                            CryptoHelper.SignAndEncryptFile(fi.FullName, fi.FullName, privateKeyStream, password, publicKeyStream, true, true, outputStream);
                        }
                    }
                    catch (Exception ex)
                    {
                        File.Delete(outputFileName);
                        throw ex;
                    }
                }

            }
        }

        [TestMethod]
        public void TestDecrypt()
        {

            //var password = "panda3@panda.com";

            var password = "panda4@panda.com";

            //var privateKeyPath = _basePath + @"\panda3_private.asc";

            var privateKeyPath = _basePath + @"\panda4_private.asc";

            var fi = new FileInfo(_basePath + @"\NickNameTable.csv.gpg"); //@"\fb_pic.jpg.gpg");  //@"\_Deliverables.txt.gpg");

            using (var privateKeyStream = File.OpenRead(privateKeyPath))
            {
                using (Stream encStream = File.OpenRead(fi.FullName))
                {
                    //using (var decryptedStream = CryptoHelper.DecryptPgpData(encStream, privateKeyStream, _dummyKeyPassword))
                    //{
                    var outputFileName = fi.FullName;
                    if (!string.IsNullOrEmpty(fi.Extension))
                    {
                        outputFileName = outputFileName.Substring(0, fi.FullName.Length - fi.Extension.Length);
                        try
                        {
                            var fiOut = new FileInfo(outputFileName);
                            if (!string.IsNullOrEmpty(fiOut.Extension))
                            {
                                outputFileName = outputFileName.Substring(0, fiOut.FullName.Length - fiOut.Extension.Length);
                                outputFileName += "_" + Guid.NewGuid().ToString("N") + fiOut.Extension;
                            }
                        }
                        catch (Exception)
                        {
                        }
                        //var decryptedString = CryptoHelper.DecryptPgpData(encStream, privateKeyStream, _dummyKeyPassword);
                        //File.WriteAllText(outputFileName, decryptedString);
                        try
                        {
                            using (var fileStream = File.Create(outputFileName))
                            {
                                CryptoHelper.DecryptPgpData(encStream, privateKeyStream, password, fileStream);
                            }
                        }
                        catch (Exception ex)
                        {
                            File.Delete(outputFileName);
                            throw ex;
                        }

                    }
                    //}
                }
            }
        }

        public static PgpKeyRingGenerator CreateKeyRingGenerator(string identity, string password)
        {

            var dateTimeNowUtc = DateTime.UtcNow;

            KeyRingParams keyRingParams = new KeyRingParams();
            keyRingParams.Password = password;
            keyRingParams.Identity = identity;
            keyRingParams.PrivateKeyEncryptionAlgorithm = SymmetricKeyAlgorithmTag.Aes256; 

            keyRingParams.SymmetricAlgorithms = new SymmetricKeyAlgorithmTag[] {
                SymmetricKeyAlgorithmTag.Aes256,
                SymmetricKeyAlgorithmTag.Aes192,
                SymmetricKeyAlgorithmTag.Aes128
            };

            keyRingParams.HashAlgorithms = new HashAlgorithmTag[] {
                HashAlgorithmTag.Sha256,
                HashAlgorithmTag.Sha1,
                HashAlgorithmTag.Sha384,
                HashAlgorithmTag.Sha512,
                HashAlgorithmTag.Sha224,
            };

            IAsymmetricCipherKeyPairGenerator generator
                = GeneratorUtilities.GetKeyPairGenerator("RSA");
            generator.Init(keyRingParams.RsaParams);


            /* Create the master (signing-only) key. */
            PgpKeyPair masterKeyPair = new PgpKeyPair(
                PublicKeyAlgorithmTag.RsaSign,
                generator.GenerateKeyPair(),
                dateTimeNowUtc);

            Debug.WriteLine("Generated master key with ID "
                + masterKeyPair.KeyId.ToString("X"));
            
            PgpSignatureSubpacketGenerator masterSubpckGen
                = new PgpSignatureSubpacketGenerator();

            var secondsUntilExpires = (long)(dateTimeNowUtc.AddDays(2) - dateTimeNowUtc).TotalSeconds;
            masterSubpckGen.SetKeyExpirationTime(false, secondsUntilExpires);

            masterSubpckGen.SetKeyFlags(false, PgpKeyFlags.CanSign
                | PgpKeyFlags.CanCertify | PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);

            masterSubpckGen.SetPreferredSymmetricAlgorithms(false,
                (from a in keyRingParams.SymmetricAlgorithms
                 select (int)a).ToArray());
            masterSubpckGen.SetPreferredHashAlgorithms(false,
                (from a in keyRingParams.HashAlgorithms
                 select (int)a).ToArray());

            /* Create a signing and encryption key for daily use. */
            PgpKeyPair encKeyPair = new PgpKeyPair(
                PublicKeyAlgorithmTag.RsaGeneral,
                generator.GenerateKeyPair(),
                dateTimeNowUtc);

            Debug.WriteLine("Generated encryption key with ID "
                + encKeyPair.KeyId.ToString("X"));

            PgpSignatureSubpacketGenerator encSubpckGen = new PgpSignatureSubpacketGenerator();
            encSubpckGen.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            encSubpckGen.SetKeyExpirationTime(false, secondsUntilExpires);

            masterSubpckGen.SetPreferredSymmetricAlgorithms(false,
                (from a in keyRingParams.SymmetricAlgorithms
                 select (int)a).ToArray());
            masterSubpckGen.SetPreferredHashAlgorithms(false,
                (from a in keyRingParams.HashAlgorithms
                 select (int)a).ToArray());

            /* Create the key ring. */
            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                PgpSignature.DefaultCertification,
                masterKeyPair,
                keyRingParams.Identity,
                keyRingParams.PrivateKeyEncryptionAlgorithm.Value,
                keyRingParams.GetPassword(),
                true,
                masterSubpckGen.Generate(),
                null,
                new SecureRandom());

            /* Add encryption subkey. */
            keyRingGen.AddSubKey(encKeyPair, encSubpckGen.Generate(), null);

            return keyRingGen;

        }

        // Define other methods and classes here
        class KeyRingParams
        {

            public SymmetricKeyAlgorithmTag? PrivateKeyEncryptionAlgorithm { get; set; }

            public SymmetricKeyAlgorithmTag[] SymmetricAlgorithms { get; set; }

            public HashAlgorithmTag[] HashAlgorithms { get; set; }

            public RsaKeyGenerationParameters RsaParams { get; set; }

            public string Identity { get; set; }

            public string Password { get; set; }
            
            public char[] GetPassword()
            {
                return Password.ToCharArray();
            }

            public KeyRingParams()
            {
                var randomGenerator = new CryptoApiRandomGenerator();
                var random = new SecureRandom(randomGenerator);

                //Org.BouncyCastle.Crypto.Tls.EncryptionAlgorithm
                RsaParams = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), random, 4096, 12); //new SecureRandom(), 2048, 12);
            }

        }

    }
}
