
namespace UnitTestProject1
{
    using System;
    using System.Configuration;
    using System.IO;
    using System.Security.Cryptography;
    // using Bouncy Castle library: http://www.bouncycastle.org/csharp/
    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Utilities.IO;

    public class CryptoHelper
    {
        //private static string Password = ConfigurationManager.AppSettings["Password"];
        //public static string PublicKey = ConfigurationManager.AppSettings["PublicKey"];
        //public static string PublicKeyPath = IoHelper.BasePath + @"\" + PublicKey;
        //// note: this should be changed if the private key is not located in the current executables path
        //private static string PrivateKeyOnly = ConfigurationManager.AppSettings["PrivateKeyOnly"];
        //private static string PrivateKeyOnlyPath = IoHelper.BasePath + @"\" + PrivateKeyOnly;

        // The majority of the functionality encrypting/decrypting came from this answer: http://stackoverflow.com/a/10210465

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        //public static string DecryptPgpData(string inputData)
        //{
        //    string output;
        //    using (Stream inputStream = IoHelper.GetStream(inputData))
        //    {
        //        using (Stream keyIn = File.OpenRead(PrivateKeyOnlyPath))
        //        {
        //            output = DecryptPgpData(inputStream, keyIn, Password);
        //        }
        //    }
        //    return output;
        //}

        //public static void Decrypt(Stream input, string outputpath, String privateKeyPath)
        //{
        //    input = PgpUtilities.GetDecoderStream(input);
        //    try
        //    {
        //        PgpObjectFactory pgpObjF = new PgpObjectFactory(input);
        //        PgpEncryptedDataList enc;
        //        PgpObject obj = pgpObjF.NextPgpObject();
        //        if (obj is PgpEncryptedDataList)
        //        {
        //            enc = (PgpEncryptedDataList)obj;
        //        }
        //        else
        //        {
        //            enc = (PgpEncryptedDataList)pgpObjF.NextPgpObject();
        //        }

        //        var akp = new AsymmetricKeyParameter(true);



        //        PgpPrivateKey privKey = GetPrivateKey(privateKeyPath);


        //        PgpPublicKeyEncryptedData pbe = enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>().First();
        //        Stream clear;
        //        clear = pbe.GetDataStream(privKey);
        //        PgpObjectFactory plainFact = new PgpObjectFactory(clear);
        //        PgpObject message = plainFact.NextPgpObject();
        //        if (message is PgpCompressedData)
        //        {
        //            PgpCompressedData cData = (PgpCompressedData)message;
        //            Stream compDataIn = cData.GetDataStream();
        //            PgpObjectFactory o = new PgpObjectFactory(compDataIn);
        //            message = o.NextPgpObject();
        //            if (message is PgpOnePassSignatureList)
        //            {
        //                message = o.NextPgpObject();
        //                PgpLiteralData Ld = null;
        //                Ld = (PgpLiteralData)message;
        //                Stream output = File.Create(outputpath + "\\" + Ld.FileName);
        //                Stream unc = Ld.GetInputStream();
        //                Streams.PipeAll(unc, output);
        //            }
        //            else
        //            {
        //                PgpLiteralData Ld = null;
        //                Ld = (PgpLiteralData)message;
        //                //Stream output = File.Create(outputpath + "\\" + Ld.FileName);
        //                Stream output = File.Create(outputpath);
        //                Stream unc = Ld.GetInputStream();
        //                Streams.PipeAll(unc, output);
        //            }
        //        }
        //    }
        //    catch (Exception e)
        //    {
        //        throw new Exception(e.Message);
        //    }
        //}


        public static string DecryptPgpData(Stream inputStream, Stream privateKeyStream, string passPhrase)
        {

            PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject pgp = null;
            if (pgpFactory != null)
            {
                pgp = pgpFactory.NextPgpObject();
            }

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedData = null;
            if (pgp is PgpEncryptedDataList)
            {
                encryptedData = (PgpEncryptedDataList)pgp;
            }
            else
            {
                encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
            }

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pubKeyData = null;
            foreach (PgpPublicKeyEncryptedData pubKeyDataItem in encryptedData.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpKeyRing, pubKeyDataItem.KeyId, passPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pubKeyData = pubKeyDataItem;
                    break;
                }
            }

            if (privateKey == null)
            {
                throw new ArgumentException("Secret key for message not found.");
            }

            PgpObjectFactory plainFact = null;
            using (Stream clear = pubKeyData.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData compressedData = (PgpCompressedData)message;
                PgpObjectFactory pgpCompressedFactory = null;

                using (Stream compDataIn = compressedData.GetDataStream())
                {
                    pgpCompressedFactory = new PgpObjectFactory(compDataIn);
                }

                message = pgpCompressedFactory.NextPgpObject();
                PgpLiteralData literalData = null;
                if (message is PgpOnePassSignatureList)
                {
                    message = pgpCompressedFactory.NextPgpObject();
                }

                literalData = (PgpLiteralData)message;

                var reader = new StreamReader(inputStream);
                string output;
                using (Stream unc = literalData.GetInputStream())
                {
                    output = IoHelper.GetString(unc);
                }
                return output;
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData literalData = (PgpLiteralData)message;
                string output;
                using (Stream unc = literalData.GetDataStream())
                {
                    output = IoHelper.GetString(unc);
                }
                return output;
            }
            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }
        }


        public static void DecryptPgpData(Stream inputStream, Stream privateKeyStream, string passPhrase, Stream outputStream)
        {

            PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject pgp = null;
            if (pgpFactory != null)
            {
                pgp = pgpFactory.NextPgpObject();
            }

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedData = null;
            if (pgp is PgpEncryptedDataList)
            {
                encryptedData = (PgpEncryptedDataList)pgp;
            }
            else
            {
                encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
            }

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pubKeyData = null;
            foreach (PgpPublicKeyEncryptedData pubKeyDataItem in encryptedData.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpKeyRing, pubKeyDataItem.KeyId, passPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pubKeyData = pubKeyDataItem;
                    break;
                }
            }

            if (privateKey == null)
            {
                throw new ArgumentException("Secret key for message not found.");
            }

            PgpObjectFactory plainFact = null;
            using (Stream clear = pubKeyData.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData compressedData = (PgpCompressedData)message;
                PgpObjectFactory pgpCompressedFactory = null;

                using (Stream compDataIn = compressedData.GetDataStream())
                {
                    pgpCompressedFactory = new PgpObjectFactory(compDataIn);
                }

                message = pgpCompressedFactory.NextPgpObject();
                PgpLiteralData literalData = null;
                if (message is PgpOnePassSignatureList)
                {
                    message = pgpCompressedFactory.NextPgpObject();
                }

                literalData = (PgpLiteralData)message;

                var reader = new StreamReader(inputStream);
                using (Stream unc = literalData.GetInputStream())
                {
                    Streams.PipeAll(unc, outputStream);
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData literalData = (PgpLiteralData)message;
                using (Stream unc = literalData.GetDataStream())
                {
                    Streams.PipeAll(unc, outputStream);
                }
            }
            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }
        }

        public static PgpSecretKey ReadSecretKey(PgpSecretKeyRingBundle pgpSecBundle)
        {

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpSecretKeyRing kRing in pgpSecBundle.GetKeyRings())
            {
                foreach (PgpSecretKey k in kRing.GetSecretKeys())
                {
                    if (k.IsSigningKey)
                    {
                        return k;
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }

        public static void SignAndEncryptFile(string actualFileName, string embeddedFileName,
             Stream privateKeyStream, string passPhrase, Stream publicKeyStream,
             bool armor, bool withIntegrityCheck, Stream outputStream)
        {
            const int BUFFER_SIZE = 1 << 16; // should always be power of 2

            if (armor)
                outputStream = new ArmoredOutputStream(outputStream);

            PgpPublicKey pubKey = ReadPublicKey(publicKeyStream);

            // Init encrypted data generator
            PgpEncryptedDataGenerator encryptedDataGenerator =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
            encryptedDataGenerator.AddMethod(pubKey);
            Stream encryptedOut = encryptedDataGenerator.Open(outputStream, new byte[BUFFER_SIZE]);

            // Init compression
            PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            Stream compressedOut = compressedDataGenerator.Open(encryptedOut);

            // Init signature
            PgpSecretKeyRingBundle pgpSecBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            var pgpSecKey = ReadSecretKey(pgpSecBundle);
            if (pgpSecKey == null)
                throw new ArgumentException(pubKey.KeyId.ToString("X") + " could not be found in specified key ring bundle.", "keyId");

            PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(passPhrase.ToCharArray());
            PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
            signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);
            var userIds = pgpSecKey.PublicKey.GetUserIds();

            string userId = null;
            foreach (string value in userIds)
            {
                // Just the first one!
                userId = value;
                break;
            }

            if (string.IsNullOrEmpty(userId))
            {
                throw new ArgumentException(string.Format("Can't find userId in signing key. KeyId '{0}'.", pubKey.KeyId.ToString("X")));
            }

            PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();
            spGen.SetSignerUserId(false, userId);
            signatureGenerator.SetHashedSubpackets(spGen.Generate());

            signatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);

            // Create the Literal Data generator output stream
            PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();

            // NOTE: Commented this out because it uses FileInfo to get stats on files and won't work properly

            FileInfo embeddedFile = new FileInfo(embeddedFileName);
            FileInfo actualFile = new FileInfo(actualFileName);

            if (!actualFile.Exists)
            {
                throw new FileNotFoundException(actualFile.FullName);
            }

            // TODO: Use lastwritetime from source file
            Stream literalOut = literalDataGenerator.Open(compressedOut, PgpLiteralData.Binary, embeddedFile.Name, actualFile.LastWriteTime, new byte[BUFFER_SIZE]);

            // Open the input file
            FileStream inputStream = actualFile.OpenRead();

            byte[] buf = new byte[BUFFER_SIZE];
            int len;
            while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, len);
                signatureGenerator.Update(buf, 0, len);
            }

            literalOut.Close();
            literalDataGenerator.Close();
            signatureGenerator.Generate().Encode(compressedOut);
            compressedOut.Close();
            compressedDataGenerator.Close();
            encryptedOut.Close();
            encryptedDataGenerator.Close();
            inputStream.Close();

            if (armor)
                outputStream.Close();
        }


        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        //public static void EncryptPgpFile(string inputFile, string outputFile)
        //{
        //    // use armor: yes, use integrity check? yes?
        //    EncryptPgpFile(inputFile, outputFile, PublicKeyPath, true, true);
        //}

        public static void EncryptPgpFile(string inputFile, string outputFile, string publicKeyFile, bool armor, bool withIntegrityCheck)
        {
            using (Stream publicKeyStream = File.OpenRead(publicKeyFile))
            {
                PgpPublicKey pubKey = ReadPublicKey(publicKeyStream);

                using (MemoryStream outputBytes = new MemoryStream())
                {
                    PgpCompressedDataGenerator dataCompressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                    PgpUtilities.WriteFileToLiteralData(dataCompressor.Open(outputBytes), PgpLiteralData.Binary, new FileInfo(inputFile));

                    dataCompressor.Close();
                    PgpEncryptedDataGenerator dataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

                    dataGenerator.AddMethod(pubKey);
                    byte[] dataBytes = outputBytes.ToArray();

                    using (Stream outputStream = File.Create(outputFile))
                    {
                        if (armor)
                        {
                            using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                            {
                                IoHelper.WriteStream(dataGenerator.Open(armoredStream, dataBytes.Length), ref dataBytes);
                            }
                        }
                        else
                        {
                            IoHelper.WriteStream(dataGenerator.Open(outputStream, dataBytes.Length), ref dataBytes);
                        }
                    }
                }
            }
        }

        // Note: I was able to extract the private key into xml format .Net expecs with this
        //public static string GetPrivateKeyXml(string inputData)
        //{
        //    Stream inputStream = IoHelper.GetStream(inputData);
        //    PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
        //    PgpObject pgp = null;
        //    if (pgpFactory != null)
        //    {
        //        pgp = pgpFactory.NextPgpObject();
        //    }

        //    PgpEncryptedDataList encryptedData = null;
        //    if (pgp is PgpEncryptedDataList)
        //    {
        //        encryptedData = (PgpEncryptedDataList)pgp;
        //    }
        //    else
        //    {
        //        encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
        //    }

        //    Stream privateKeyStream = File.OpenRead(PrivateKeyOnlyPath);

        //    // find secret key
        //    PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
        //    PgpPrivateKey privateKey = null;

        //    foreach (PgpPublicKeyEncryptedData pked in encryptedData.GetEncryptedDataObjects())
        //    {
        //        privateKey = FindSecretKey(pgpKeyRing, pked.KeyId, Password.ToCharArray());
        //        if (privateKey != null)
        //        {
        //            //pubKeyData = pked;
        //            break;
        //        }
        //    }

        //    // get xml:
        //    RsaPrivateCrtKeyParameters rpckp = ((RsaPrivateCrtKeyParameters)privateKey.Key);
        //    RSAParameters dotNetParams = DotNetUtilities.ToRSAParameters(rpckp);
        //    RSA rsa = RSA.Create();
        //    rsa.ImportParameters(dotNetParams);
        //    string xmlPrivate = rsa.ToXmlString(true);

        //    return xmlPrivate;
        //}
    }
}
