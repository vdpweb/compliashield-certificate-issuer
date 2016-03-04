
namespace PgpCertificateIssuer
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Crypto.Prng;
    using ConsoleHelpers;

    public class PgpKeyRingHelper
    {


        public static PgpKeyRingGenerator CreateKeyRingGenerator(string identity, DateTime expirationDate, string passphrase, bool use4096)
        {

            var certCreatedOn = DateTime.UtcNow;

            KeyRingParams keyRingParams = new KeyRingParams(use4096);
            keyRingParams.Password = passphrase;
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
                certCreatedOn);

            Debug.WriteLine("Generated master key with ID "
                + masterKeyPair.KeyId.ToString("X"));

            PgpSignatureSubpacketGenerator masterSubpckGen = new PgpSignatureSubpacketGenerator();

            var secondsUntilExpires = (long)(expirationDate - certCreatedOn).TotalSeconds + 1;
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
                certCreatedOn);

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
                keyRingParams.Password == null ? null : keyRingParams.GetPassword(),
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

            public KeyRingParams(bool use4096)
            {
                var randomGenerator = new CryptoApiRandomGenerator();
                var random = new SecureRandom(randomGenerator);

                //Org.BouncyCastle.Crypto.Tls.EncryptionAlgorithm
                if (use4096)
                {
                    RsaParams = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), random, 4096, 12); //new SecureRandom(), 2048, 12);
                }
                else
                {
                    RsaParams = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), random, 2048, 12);
                }
            }

        }
    }
}
