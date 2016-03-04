

namespace PgpCertificateIssuer
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.Crypto.Prng;
    using ConsoleHelpers;
    using System.Threading;


    class Program
    {

        static int READLINE_BUFFER_SIZE = 1024;

        public const string DIVIDER = "---------------";

        private static bool _runOnce;
        private static bool _runUnattended;
        private static string _argsCommand;
        private static bool _exitInsteadOfReturn;

        private static IDictionary<string, CommandDefintion> _commands = GetCommandDefitions();

        static void Main(string[] args)
        {

            var hasArgs = args != null && args.Any();

            System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
            FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            string version = fvi.FileVersion;

            if (hasArgs)
            {
                Console.WriteLine();
            }

            Console.WriteLine("PGP Certificate Issuer Console");
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

            // extending for long passphrases
            Console.SetIn(new StreamReader(Console.OpenStandardInput(8192)));





            if (hasArgs)
            {
                Console.WriteLine();
            }

            if (!hasArgs)
            {
                _exitInsteadOfReturn = false;
                ProcessManual();
            }
            else
            {
                _exitInsteadOfReturn = true;
                RunArgs(args);
            }
        }


        static void RunArgs(string[] args)
        {

#if DEBUG
            Console.WriteLine();
            Console.WriteLine("Pausing for debug...");
            Thread.Sleep(15000);
#endif

            _runUnattended = true;
            var commands = GetCommandDefitions();

            if (args == null || !args.Any())
            {
                Console.Write("No arguments received.");
                Console.WriteLine();
                ReadKeyOrReturnAfterLapse();
                return;
            }

            var command = args.First().ToLower();
            if (!commands.ContainsKey(command))
            {
                Console.Write("Invalid command.");
                Console.WriteLine();
                ReadKeyOrReturnAfterLapse();
                return;
            }

            var cd = commands[command];

            IDictionary<string, string> argumentDictionary;
            IEnumerable<string> errors;
            var isValid = cd.TryParseArguments(args, out argumentDictionary, out errors);

            if (!isValid)
            {
                if (errors == null || !errors.Any())
                {
                    Console.WriteLine("Invalid arguments received.");
                }
                else
                {
                    Console.WriteLine("Invalid arguments received:");
                    foreach (var error in errors)
                    {
                        Console.WriteLine(error);
                        ReadKeyOrReturnAfterLapse();
                        return;
                    }
                }
                Console.WriteLine();
                ReadKeyOrReturnAfterLapse();
                return;
            }

            int i = 0;
            foreach (var arg in argumentDictionary)
            {
                if (arg.Key.ToLower() != "passphrase")
                {
                    i++;
                    Console.WriteLine("[" + i.ToString() + "] " + arg.Key + "\t" + arg.Value);
                }
            }

            if (command == "gen-key")
            {
                var pubring = argumentDictionary["pubring"];
                var secring = argumentDictionary["secring"];
                var nameReal = argumentDictionary["name-real"];
                var nameEmail = argumentDictionary["name-email"];
                var keyLength = argumentDictionary["key-length"];
                var expirationAsString = argumentDictionary["expire-date"];

                DateTime expireDate;
                var isValidExp = DateTime.TryParse(expirationAsString, out expireDate);
                if (!isValidExp)
                {
                    Console.WriteLine("ERROR: Argument 'expire-date' value could not be paresed into a valid expiration date.");
                    ReadKeyOrReturnAfterLapse();
                    return;
                }

                var passphrase = argumentDictionary["passphrase"];
                if (string.IsNullOrWhiteSpace(passphrase) && !argumentDictionary.ContainsKey("no-protection"))
                {
                    Console.WriteLine("ERROR: Either a 'passphrase' value is required or you must pass the 'no-protection' argument.");
                    ReadKeyOrReturnAfterLapse();
                    return;
                }
                bool use4096 = true;
                if (keyLength == "2048")
                {
                    use4096 = false;
                }

                GenerateKey(pubring, secring, nameReal, nameEmail, expireDate, passphrase, use4096);
            }

        }

        static void ProcessManual()
        {

            //string pubring, string secring, string nameReal, string nameEmail, string passphrase, bool use4096

            string pubring;
            while (!TryGetValue("pubring", out pubring))
            {

            }

            string secring;
            while (!TryGetValue("secring", out secring))
            {

            }

            string nameReal;
            while (!TryGetValue("name-real", out nameReal))
            {

            }
            string nameEmail;
            while (!TryGetEmail("name-email", out nameEmail))
            {

            }
            DateTime expireDate;
            while (!TryGetexpireDate("expire-date", out expireDate))
            {

            }
            string passphrase;
            while (!TrySetPassphrase(false, out passphrase))
            {
            }

            bool use4096 = true;
            Console.WriteLine("Use 4096 bit key length?");
            if (IsYforContinue())
            {
                Console.Write("4096 bit key length selected.");
            }
            else
            {
                Console.Write("Use 2048 bit key length?");
                if (IsYforContinue())
                {
                    Console.Write("2048 bit key length selected.");
                    use4096 = false;
                }
            }

            GenerateKey(pubring, secring, nameReal, nameEmail, expireDate, passphrase, use4096);

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine(DIVIDER);
            Console.WriteLine();
            Console.WriteLine("key-gen command starting...");
            Console.WriteLine();

            ProcessManual();
        }

        static bool TryGetexpireDate(string parameter, out DateTime expireDate)
        {
            string expirationAsString;
            while (!TryGetValue(parameter, out expirationAsString))
            {

            }
            DateTime expire1;
            var isValid = DateTime.TryParse(expirationAsString, out expire1);
            if (!isValid)
            {
                return TryGetexpireDate(parameter, out expireDate);
            }
            TimeZone zone = TimeZone.CurrentTimeZone;
            expireDate = zone.ToUniversalTime(expire1);
            return true;
        }

        static bool TrySetPassphrase(bool isVerify, out string passphrase)
        {
            var parameter = "passphrase";
            if (isVerify)
            {
                parameter = "verify passphrase";
            }
            while (!TryGetPassphrase(parameter, isVerify, out passphrase))
            {
                if (!isVerify)
                {
                    Console.Write("Skip passphrase? ");
                    if (IsYforContinue())
                    {
                        passphrase = null;
                        return true;
                    }
                }
            }

            if (!isVerify)
            {
                // verify
                string verifyPassphrase;
                while (!TryGetPassphrase(parameter, true, out verifyPassphrase))
                {
                }
                if (passphrase != verifyPassphrase)
                {
                    Console.WriteLine("Passphrases do not match. Please re-enter your passphrase again.");
                    return TrySetPassphrase(false, out passphrase);
                }
                else
                {
                    return true;
                }
            }
            else
            {
                return true;
            }
        }


        static void GenerateKey(string pubring, string secring, string nameReal, string nameEmail, DateTime expireDate, string passphrase, bool use4096)
        {
            if (string.IsNullOrEmpty(pubring))
            {
                Console.WriteLine("ERROR: 'pubring' is not a valid file path.");
                ReadKeyOrReturnAfterLapse();
                return;
            }

            try
            {
                var fi = new FileInfo(pubring);
                if (fi.Exists)
                {
                    Console.WriteLine("ERROR: 'pubring' file already exists.");
                    ReadKeyOrReturnAfterLapse();
                    return;
                }
                if (!fi.Directory.Exists)
                {
                    fi.Directory.Create();
                }
            }
            catch { }


            if (string.IsNullOrEmpty(secring))
            {
                Console.WriteLine("ERROR: 'secring' is not a valid file path.");
                ReadKeyOrReturnAfterLapse();
                return;
            }

            try
            {
                var fi = new FileInfo(secring);
                if (fi.Exists)
                {
                    Console.WriteLine("ERROR: 'secring' file already exists.");
                    ReadKeyOrReturnAfterLapse();
                    return;
                }
                if (!fi.Directory.Exists)
                {
                    fi.Directory.Create();
                }
            }
            catch { }

            if (string.IsNullOrEmpty(nameReal))
            {
                Console.WriteLine("ERROR: 'nameReal' is not valid.");
                ReadKeyOrReturnAfterLapse();
                return;
            }
            if (string.IsNullOrEmpty(nameEmail) || !nameEmail.IsValidEmailAddress())
            {
                Console.WriteLine("ERROR: 'nameEmail' is not valid.");
                ReadKeyOrReturnAfterLapse();
                return;
            }
            if (!string.IsNullOrWhiteSpace(passphrase))
            {
                if (passphrase.Length < 7)
                {
                    Console.WriteLine("ERROR: 'passphrase' must be at least 7 characters long.");
                    ReadKeyOrReturnAfterLapse();
                    return;
                }
                if (!passphrase.Any(c => char.IsDigit(c)))
                {
                    Console.WriteLine("ERROR: 'passphrase' must contain at least 1 number.");
                    ReadKeyOrReturnAfterLapse();
                    return;
                }
            }

            //string pubring, string secring, string nameReal, string nameEmail, DateTime expireDate, string passphrase, bool use4096
            Console.WriteLine();

            Console.WriteLine("Key parameters:");
            Console.WriteLine(DIVIDER);
            Console.WriteLine("pubring: " + pubring);
            Console.WriteLine("secring: " + secring);
            Console.WriteLine("name-real: " + nameReal);
            Console.WriteLine("name-email: " + nameEmail);
            Console.WriteLine("expire-date: " + expireDate.ToString());
            if (use4096)
            {
                Console.WriteLine("key-length: 4096");
            }
            else
            {
                Console.WriteLine("key-length: 2048");
            }
            if (string.IsNullOrWhiteSpace(passphrase))
            {
                Console.WriteLine("WARNING * * * * * * * *");
                Console.WriteLine("The private key does not have a passphrase.");
                Console.WriteLine("It is strongly recommended that you use a passphrase with your private key.");
                Console.WriteLine("* * * * * * * * * * * *");
            }

            Console.WriteLine(DIVIDER);

            // check to execute
            if (!IsYforContinue())
            {
                Console.WriteLine();
                Console.WriteLine("Canceling key generation.");
                Console.WriteLine();
                return;
            }

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine(DIVIDER);
            Console.WriteLine("Please wait while we generate your keys. Generating secure keys takes time...");
            Console.WriteLine(DIVIDER);
            Console.WriteLine();

            try
            {

                PgpKeyRingGenerator krgen = PgpKeyRingHelper.CreateKeyRingGenerator(nameReal + " <" + nameEmail + ">", expireDate, passphrase, use4096);

                // Generate public key ring, dump to file.
                PgpPublicKeyRing pkr = krgen.GeneratePublicKeyRing();
                BufferedStream pubout = new BufferedStream(new FileStream(pubring, System.IO.FileMode.Create));
                pkr.Encode(pubout);
                pubout.Close();

                // Generate private key, dump to file.
                PgpSecretKeyRing skr = krgen.GenerateSecretKeyRing();
                BufferedStream secout = new BufferedStream(new FileStream(secring, System.IO.FileMode.Create));
                skr.Encode(secout);
                secout.Close();

                Console.WriteLine();
                Console.WriteLine("PGP key pairs successfully generated.");
                Console.WriteLine();
                ReadKeyOrReturnAfterLapse();
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("Exception: " + ex.GetType().Name + " - " + ex.Message);
                Console.WriteLine();
                ReadKeyOrReturnAfterLapse();
            }
        }

        #region helpers

        static bool IsYforContinue()
        {
            if (_runUnattended)
            {
                return true;
            }
            Console.WriteLine("Enter Y to continue or any other key to cancel.");
            Console.Write("Continue: > ");
            var key = Console.ReadLine();
            Console.WriteLine();
            if (key.EqualsCaseInsensitive("Y"))
            {
                return true;
            }
            return false;
        }

        static void ReadKeyOrReturnAfterLapse()
        {
            if (_runUnattended)
            {
                Thread.Sleep(3000);
                return; // ActionOption.Continue;
            }

            Console.WriteLine("Press any key to continue...");

            DateTime quit = DateTime.UtcNow.AddMinutes(5);
            DateTime beginWait = DateTime.UtcNow;
            while (!Console.KeyAvailable && quit > beginWait)
            {
                System.Threading.Thread.Sleep(250);
            }

            if (Console.KeyAvailable)
            {
                // clear the key
                Console.ReadKey();
            }
        }

        static bool TryGetValue(string parameter, out string value)
        {
            var cmdDef = _commands["gen-key"];
            if (cmdDef.Parameters.ContainsKey(parameter))
            {
                var paramDef = cmdDef.Parameters[parameter];
                if (!string.IsNullOrEmpty(paramDef.HelpText))
                {
                    Console.WriteLine("Parameter '" + parameter + "' - " + paramDef.HelpText);
                }
            }

            Console.Write("Enter '" + parameter + "' value: > ");
            value = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(value))
            {
                Console.WriteLine("Value not valid.");
                return false;
            }
            return true;
        }

        static bool TryGetPassphrase(string parameter, bool isVerify, out string value)
        {
            var cmdDef = _commands["gen-key"];
            if (cmdDef.Parameters.ContainsKey(parameter))
            {
                var paramDef = cmdDef.Parameters[parameter];
                if (!string.IsNullOrEmpty(paramDef.HelpText))
                {
                    Console.WriteLine("Parameter '" + parameter + "' - " + paramDef.HelpText);
                }
            }
            Console.Write("Enter '" + parameter + "' value: > ");

            value = null;
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);

                // Backspace Should Not Work
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    value += key.KeyChar;
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && value.Length > 0)
                    {
                        value = value.Substring(0, (value.Length - 1));
                        Console.Write("\b \b");
                    }
                }
            }
            // Stops Receving Keys Once Enter is Pressed
            while (key.Key != ConsoleKey.Enter);
            Console.WriteLine(); // there hasn't been a new line

            if (!string.IsNullOrEmpty(value) && !isVerify)
            {
                if (value.Length < 7)
                {
                    Console.WriteLine("ERROR: '" + parameter + "' must be at least 7 characters long.");
                    value = null;
                    return TryGetPassphrase(parameter, isVerify, out value);
                }
                if (!value.Any(c => char.IsDigit(c)))
                {
                    Console.WriteLine("ERROR: '" + parameter + "' must contain at least 1 number.");
                    return TryGetPassphrase(parameter, isVerify, out value);
                }
                return true;
            }

            return !string.IsNullOrWhiteSpace(value);
        }

        static bool TryGetEmail(string parameter, out string value)
        {
            Console.Write("Enter " + parameter + ": > ");
            value = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(value))
            {
                value = null;
                Console.WriteLine("Value not valid.");
                return false;
            }
            if (!value.IsValidEmailAddress())
            {
                value = null;
                Console.WriteLine("Value not valid.");
                return false;
            }
            return true;
        }

        static IDictionary<string, CommandDefintion> GetCommandDefitions()
        {
            var dic = new Dictionary<string, CommandDefintion>(StringComparer.OrdinalIgnoreCase);

            var def = new CommandDefintion() { CommandName = "gen-key" };

            def.SetParameterDefinition("pubring", true, "File path to output the public key ring.");
            def.SetParameterDefinition("secring", true, "File path to output the secret key ring.");

            def.SetParameterDefinition("name-real", true, "Identity name.");
            def.SetParameterDefinition("name-email", true, RegExPatterns.EmailAddress, "Invalid email address.", "Identity email address.");

            def.SetParameterDefinition("expire-date", true, "Expiration date YYYY-MM-DD or YYYY-MM-DD HH:MM:SS format.");

            // one or the other is required
            def.SetParameterDefinition("passphrase", false, "The passphrase to protect the private key.");
            def.SetParameterDefinition("no-protection", false, "If 'passphrase' argument is not included must pass argument 'no-protection' to confirm.");

            def.SetParameterDefinition("key-length", false, "^(2048|4096)$", "Must be 2048 or 4096", "Key strength of 2048 or 4096.");



            dic[def.CommandName] = def;

            return dic;
        }

        #endregion
    }
}
