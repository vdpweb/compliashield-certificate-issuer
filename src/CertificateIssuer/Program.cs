using System;
using System.Collections.Generic;
using System.Linq;

namespace CompliaShield.CertificateIssuer.ConsoleApp
{
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using System.Text.RegularExpressions;
    using System.Security.Cryptography;

    using ICSharpCode.SharpZipLib;
    using ICSharpCode.SharpZipLib.Zip;
    using ICSharpCode.SharpZipLib.Core;
    using System.Diagnostics;
    using ICSharpCode.SharpZipLib.Checksums;

    class Program
    {
        static void Main(string[] args)
        {


            System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
            FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            string version = fvi.FileVersion;

            Console.WriteLine("Certificate Issuer Console");
            Console.WriteLine("version " + version);
            Console.WriteLine("");
            Console.WriteLine("(c) 2016 CompliaShield LLC. All rights reserved. ");
            Console.WriteLine("");
            Console.WriteLine("");

            Console.WriteLine("WARNING: This is a non-commercial product to be used at your own risk.");
            Console.WriteLine("No warranties, security claims or other assertions are offered with this software.");
            Console.WriteLine("This software is offered 'as is'.");
            Console.WriteLine("");
            Console.WriteLine("");

            if (args == null || !args.Any())
            {
                ProcessManual();
            }
            else
            {
                Console.Write("Args not accepted yet.");
                ProcessManual();
            }

        }

        static void ProcessManual()
        {
            Console.Write("Enter certificate CN > ");
            var cn = Console.ReadLine();

            DateTime expireOnUtc = DateTime.MinValue;
            var dateHandled = false;
            while (!dateHandled)
            {
                dateHandled = HandleExpiration(out expireOnUtc);
            }
            FileInfo zipFileInfo = null;
            var filePathHandled = false;
            while (!filePathHandled)
            {
                filePathHandled = HandleFilePath(cn, out zipFileInfo);
            }
            System.Security.Cryptography.X509Certificates.X509Certificate2 rootX509Certificate2 = null;
            var rootHandled = false;
            while (!rootHandled)
            {
                rootHandled = HandleRoot(out rootX509Certificate2);
            }

            var serialNumberHandled = false;
            long serialNumber = 0;
            while (!serialNumberHandled)
            {
                serialNumberHandled = HandleSerialNumber(out serialNumber);
            }

            bool isCertificateAuthority = false;
            //if (rootX509Certificate2 == null)
            //{
            // create a root
            Console.Write("Mark as certificate authority? (Y + ENTER for yes) > ");
            var resp = Console.ReadLine();
            if (!string.IsNullOrEmpty(resp) && resp.ToLower() == "y")
            {
                isCertificateAuthority = true;
            }
            //}

            bool includePemPrivateKey = false;
            Console.Write("Include full key PEM text file? [WARNING: Includes PRIVATE key!] (Y + ENTER for yes) > ");
            var respPrivatePem = Console.ReadLine();
            if (!string.IsNullOrEmpty(respPrivatePem) && respPrivatePem.ToLower() == "y")
            {
                includePemPrivateKey = true;
            }

            Console.WriteLine();
            Console.WriteLine("Generating files...");
            Console.WriteLine();

            string thumbprint = null;
            string pemPrivateKey = null;
            string pemPublicCert = null;
            byte[] cerData = null;
            byte[] pkcs12Data;
            string password = null;
            try
            {

                if (rootX509Certificate2 == null)
                {
                    CertificateGenerator.GenerateRootCertificate(cn, serialNumber, expireOnUtc, isCertificateAuthority, out thumbprint, out pemPrivateKey, out pemPublicCert, out cerData, out pkcs12Data, out password);
                }
                else
                {
                    // create a signed certificate
                    CertificateGenerator.GenerateCertificate(cn, serialNumber, expireOnUtc, isCertificateAuthority, rootX509Certificate2, out thumbprint, out pemPrivateKey, out pemPublicCert, out cerData, out pkcs12Data, out password);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception generating certificate...");
                Console.WriteLine(ex.GetType().FullName + ": " + ex.Message);
                ProcessManual();
                return;
            }

            try
            {
                if (!includePemPrivateKey)
                {
                    pemPrivateKey = null;
                }
                HandleZipOutput(zipFileInfo, thumbprint, pemPublicCert, cerData, pemPrivateKey, pkcs12Data, password);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception zipping output...");
                Console.WriteLine(ex.GetType().FullName + ": " + ex.Message);
                ProcessManual();
                return;
            }

            ProcessManual();
        }

        static void HandleZipOutput(FileInfo zipFileInfo, string thumbprint, string pemPublicCert, byte[] cerData, string pemPrivateKey, byte[] pkcs12Data, string password)
        {
            var baseCn = zipFileInfo.Name;
            if (baseCn.EndsWith(".zip"))
            {
                baseCn = baseCn.Substring(0, baseCn.Length - 4);
            }

            using (ZipOutputStream zipOutputStream = new ZipOutputStream(File.Create(zipFileInfo.FullName)))
            {

                //zipOutputStream.SetLevel(9);

                zipOutputStream.UseZip64 = UseZip64.Off; // for OSX to be happy

                if (cerData != null)
                {
                    ZipEntry entry = new ZipEntry(baseCn + "/" + baseCn + "_asBytes.cer");
                    entry.DateTime = DateTime.Now;
                    zipOutputStream.PutNextEntry(entry);

                    byte[] buffer = new byte[4096];
                    using (Stream stream = new MemoryStream(cerData))
                    {
                        int sourceBytes;
                        do
                        {
                            sourceBytes = stream.Read(buffer, 0, buffer.Length);
                            zipOutputStream.Write(buffer, 0, sourceBytes);
                        } while (sourceBytes > 0);
                    }
                }

                if (pkcs12Data != null)
                {
                    ZipEntry entry = new ZipEntry(baseCn + "/" + baseCn + ".pfx");
                    entry.DateTime = DateTime.Now;
                    zipOutputStream.PutNextEntry(entry);

                    byte[] buffer = new byte[4096];
                    using (Stream stream = new MemoryStream(pkcs12Data))
                    {
                        int sourceBytes;
                        do
                        {
                            sourceBytes = stream.Read(buffer, 0, buffer.Length);
                            zipOutputStream.Write(buffer, 0, sourceBytes);
                        } while (sourceBytes > 0);
                    }
                }

                if (!string.IsNullOrEmpty(pemPrivateKey))
                {
                    MemoryStream ms = new MemoryStream();
                    StreamWriter sw = new StreamWriter(ms);
                    sw.Write(pemPrivateKey);
                    sw.Flush(); //This is required or you get a blank text file :)
                    ms.Position = 0;
                    ZipEntry entry = new ZipEntry(baseCn + "/" + baseCn + ".pem");
                    entry.DateTime = DateTime.Now;
                    zipOutputStream.PutNextEntry(entry);
                    zipOutputStream.Write(ms.ToArray(), 0, Convert.ToInt32(ms.Length));
                }

                if (!string.IsNullOrEmpty(pemPublicCert))
                {
                    MemoryStream ms = new MemoryStream();
                    StreamWriter sw = new StreamWriter(ms);
                    sw.Write(pemPublicCert);
                    sw.Flush(); //This is required or you get a blank text file :)
                    ms.Position = 0;

                    ZipEntry entry = new ZipEntry(baseCn + "/" + baseCn + ".cer");
                    entry.DateTime = DateTime.Now;
                    zipOutputStream.PutNextEntry(entry);
                    zipOutputStream.Write(ms.ToArray(), 0, Convert.ToInt32(ms.Length));
                }

                if (!string.IsNullOrEmpty(thumbprint))
                {
                    MemoryStream ms = new MemoryStream();
                    StreamWriter sw = new StreamWriter(ms);
                    sw.Write(thumbprint);
                    sw.Flush(); //This is required or you get a blank text file :)
                    ms.Position = 0;
                    ZipEntry entry = new ZipEntry(baseCn + "/" + baseCn + "_thumbprint.txt");
                    entry.DateTime = DateTime.Now;
                    zipOutputStream.PutNextEntry(entry);
                    zipOutputStream.Write(ms.ToArray(), 0, Convert.ToInt32(ms.Length));
                }

                if (!string.IsNullOrEmpty(password))
                {
                    MemoryStream ms = new MemoryStream();
                    StreamWriter sw = new StreamWriter(ms);
                    sw.Write(password);
                    sw.Flush(); //This is required or you get a blank text file :)
                    ms.Position = 0;
                    ZipEntry entry = new ZipEntry(baseCn + "/" + baseCn + "_password.txt");
                    entry.DateTime = DateTime.Now;
                    zipOutputStream.PutNextEntry(entry);
                    zipOutputStream.Write(ms.ToArray(), 0, Convert.ToInt32(ms.Length));
                }

                zipOutputStream.Finish();
                zipOutputStream.Flush();
                zipOutputStream.Close();
            }

            Console.WriteLine(string.Format("Certificate files output to '{0}'.", zipFileInfo.FullName));
            Console.WriteLine("---------------------------------------");
            Console.Write(string.Format("Open the directory? (Y + ENTER for yes) > ", zipFileInfo.FullName));
            var resp = Console.ReadLine();
            if (!string.IsNullOrEmpty(resp) && resp.ToLower() == "y")
            {
                string fileToSelect = zipFileInfo.FullName;
                string args = string.Format("/Select, \"{0}\"", fileToSelect);
                Console.WriteLine("Opening directory...");
                ProcessStartInfo pfi = new ProcessStartInfo("Explorer.exe", args);
                System.Diagnostics.Process.Start(pfi);
            }

            Console.WriteLine();
            Console.WriteLine("---------------------------------------");
            Console.WriteLine("Operation complete.");
            Console.WriteLine("---------------------------------------");
            Console.WriteLine();
            Console.WriteLine();
        }

        static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        static bool HandleFilePath(string cn, out FileInfo zipFileInfo)
        {
            Console.Write("Enter output directory location (default, press ENTER) > ");
            var output = @"C:\certificate";
            var enteredOutput = Console.ReadLine();
            if (!string.IsNullOrEmpty(enteredOutput))
            {
                output = enteredOutput;
            }
            try
            {
                var dir = new DirectoryInfo(output);
                if (!dir.Exists)
                {
                    Console.WriteLine("The requested directory does not exist.");
                    Console.Write("Create it now? (Y + ENTER for yes) > ");
                    var resp = Console.ReadLine();
                    if (string.IsNullOrEmpty(resp))
                    {
                        zipFileInfo = null;
                        return false;
                    }
                    else if (resp.ToLower() == "y")
                    {
                        dir.Create();
                    }
                    else
                    {
                        zipFileInfo = null;
                        return false;
                    }
                }

                var fileName = FileNameSafeCharacters(cn) + ".zip";

                zipFileInfo = new FileInfo(Path.Combine(dir.FullName, fileName));
                if (zipFileInfo.Exists)
                {
                    Console.WriteLine("The requested file path '{0}' already exists.", zipFileInfo.FullName);
                    Console.Write(string.Format(" Delete the old file? (Y + ENTER for yes, N + ENTER for no) > ", zipFileInfo.FullName));
                    var resp = Console.ReadLine();
                    if (string.IsNullOrEmpty(resp))
                    {
                        zipFileInfo = null;
                        return false;
                    }
                    else if (resp.ToLower() == "y")
                    {
                        zipFileInfo.Delete();
                    }
                    else
                    {
                        zipFileInfo = null;
                        return false;
                    }
                }
                return true;
            }
            catch
            {
                Console.WriteLine("Could not use the requrested directory.");
                zipFileInfo = null;
                return false;
            }

        }

        static bool HandleExpiration(out DateTime expireOn)
        {
            Console.Write("Enter expiration date yyyy/mm/dd > ");
            var exp = Console.ReadLine();
            DateTime tempExpDate;
            var validDate = DateTime.TryParse(exp, out tempExpDate);
            if (!validDate || tempExpDate < DateTime.Now)
            {
                expireOn = DateTime.MinValue;
                Console.Write("Invalid date.");
                return false;
            }

            var ticksOffset = (DateTime.UtcNow.Ticks - DateTime.Now.Ticks);
            expireOn = new DateTime(tempExpDate.Date.Ticks + ticksOffset);
            Console.WriteLine(string.Format("Certificate set to expire: {0:ddd, MMM d, yyyy}", expireOn));
            return true;
        }

        static bool HandleRoot(out System.Security.Cryptography.X509Certificates.X509Certificate2 rootCertificate)
        {

            //Console.Write("Use a root certificate? (Y + ENTER for yes or anything else to skip) > ");
            //var resp = Console.ReadLine();

            //if (resp.ToLower() != "y")
            //{
            //    Console.WriteLine("No issuing certificate. Certificate will be issued as a root certificate.");
            //    rootCertificate = null;
            //    return true;
            //}

            Console.Write("Enter thumbprint or path to PFX of issuing CA (ENTER to skip) > ");
            var path = Console.ReadLine();
            if (string.IsNullOrEmpty(path))
            {
                Console.WriteLine("No issuing certificate. Certificate will be issued as a root certificate.");
                rootCertificate = null;
                return true;
            }

            if(path.StartsWith("\"") && path.EndsWith("\""))
            {
                path = path.Substring(1, path.Length - 2);
            }

            if (path.Length == 40 && !path.Contains(@"\") && !path.Contains("/"))
            {
                var certificateStore = new CertificateStore();
                try
                {
                    rootCertificate = certificateStore.GetCertificate(path);
                    if (rootCertificate != null)
                    {
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    Console.Write("Exception...");
                    Console.Write(ex.Message);
                }
                rootCertificate = null;
                Console.WriteLine("Could not read issuing certificate.");
                return false;
            }
            else
            {
                try
                {
                    var fi = new FileInfo(path);
                    if (fi.Exists)
                    {
                        var bytes = File.ReadAllBytes(fi.FullName);
                        Console.Write("Enter issuing root PFX password (ENTER to skip) > ");
                        var rootPassword = ConsoleHelpers.CommandHelper.ReadPassword();
                        rootCertificate = CertificateGenerator.GetX509Certificate2FromBytes(bytes, rootPassword);
                        if (rootPassword == null || !rootCertificate.HasPrivateKey)
                        {
                            Console.WriteLine("Could not load private key.");
                            return false;
                        }
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    Console.Write("Exception...");
                    Console.Write(ex.Message);
                }
                rootCertificate = null;
                Console.WriteLine("Could not read issuing certificate.");
                return false;
            }
        }

        static bool HandleSerialNumber(out long serialNumber)
        {
            Console.Write("Type a serial number for this certificate or ENTER for random > ");
            var serialInput = Console.ReadLine();
            if (string.IsNullOrEmpty(serialInput))
            {
                serialNumber = 0;
                return true;
            }
            else
            {
                var isValid = long.TryParse(serialInput, out serialNumber);
                if (!isValid)
                {
                    serialNumber = 0;
                    Console.WriteLine(string.Format("Could not use '{0}' as a serial number.", serialInput));
                    return false;
                }
                return true;
            }
        }

        private static string FileNameSafeCharacters(string input)
        {
            if (input == null)
            {
                return string.Empty;
            }
            string removeInvalidChars = "[^a-zA-Z 0-9._\\-]+";
            input = Regex.Replace(input, removeInvalidChars, string.Empty);
            return input;
        }

    }
}
