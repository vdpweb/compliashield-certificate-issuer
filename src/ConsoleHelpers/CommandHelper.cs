
namespace ConsoleHelpers
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;


    public static class CommandHelper
    {

        public static bool TryParseArguments(this CommandDefintion commandDefinition, IEnumerable<string> args, out IDictionary<string, string> argumentDictionary, out IEnumerable<string> errors)
        {
            string command = null;
            argumentDictionary = null;
            errors = null;
            try
            {
                argumentDictionary = args.ParseArguments(out command);
            }
            catch (FormatException ex)
            {
                errors = new string[] { ex.Message };
                return false;
            }

            var errorList = new List<string>();

            foreach (var param in commandDefinition.Parameters)
            {
                if (param.Value.ArgumentIsRequired && (!argumentDictionary.ContainsKey(param.Key) || string.IsNullOrEmpty(argumentDictionary[param.Key])))
                {
                    errorList.Add(string.Format("Parameter '{0}' is required.", param.Key));
                    continue;
                }
                if (!string.IsNullOrEmpty(param.Value.ArgumentRegExMatchPattern) && argumentDictionary.ContainsKey(param.Key) && !string.IsNullOrWhiteSpace(argumentDictionary[param.Key]))
                {
                    var fullMatch = argumentDictionary[param.Key].IsFullMatch(param.Value.ArgumentRegExMatchPattern);
                    if (!fullMatch)
                    {
                        errorList.Add(string.Format("Parameter '{0}' has an invalid argument. " + param.Value.ArgumentRegExErrorMessage, param.Key));
                        continue;
                    }
                }
            }

            foreach (var item in argumentDictionary)
            {
                if (!commandDefinition.Parameters.ContainsKey(item.Key))
                {
                    errorList.Add(string.Format("Parameter '{0}' is not allowed.", item.Key));
                }
            }
            if (errorList.Any())
            {
                errors = errorList;
                return false;
            }
            return true;
        }

        public static IDictionary<string, string> ParseArguments(this IEnumerable<string> args, out string command)
        {
            if (args == null || !args.Any())
            {
                throw new ArgumentException("args");
            }

            var list = args.ToList();
            int length = list.Count;

            // set the command from first position
            command = list[0];

            var dic = new Dictionary<string, string>();

            var exList = new List<FormatException>();

            // now start with the args
            for (int i = 1; i < length; i++)
            {
                string value;
                FormatException ex;
                var cmd = list[i];
                if (cmd.StartsWith("--"))
                {
                    cmd = cmd.Substring(2);
                }
                else if (cmd.StartsWith("-"))
                {
                    cmd = cmd.Substring(1);
                }
                cmd = cmd.ToLower();
                if (list.TryGetArgument(cmd, out value, out ex))
                {
                    cmd = GetCommand(cmd); // handle equals syntax
                    dic[cmd] = value;
                }
                if (ex != null)
                {
                    throw ex;
                }
                // skip an extra
                i++;
            }
            return dic;
        }

        private static string GetCommand(string argument)
        {
            if (argument.Contains("="))
            {
                var items = argument.SplitStringAndTrim("=").ToArray();
                if (items.Count() > 1)
                {
                    return items[0];
                }
            }
            return argument;
        }

        public static bool TryGetArgument(this List<string> args, string argument, out string value, out FormatException exception)
        {

            if (string.IsNullOrEmpty(argument))
            {
                throw new ArgumentException("argument");
            }

            // always go lower per comannd line specs
            argument = argument.ToLower();

            exception = null;
            int i = 0;
            value = null; // some parameters might be present, but not specify and value

            foreach (var item in args)
            {
                var cmd = item;

                // this is not a command, but a value
                if (!cmd.StartsWith("-"))
                {
                    // not a parameter so we move on
                    i++;
                    continue;
                }
                if (cmd.StartsWith("--"))
                {
                    cmd = cmd.Substring(2);
                }
                else if (cmd.StartsWith("-"))
                {
                    cmd = cmd.Substring(1);
                }

                cmd = cmd.ToLower();

                i++;

                // the equals format for a parameters
                if (cmd.Contains("="))
                {
                    // check to see if this our asked for parameter
                    if (!cmd.EqualsCaseInsensitive(argument))
                    {
                        continue;
                    }

                    var items = cmd.SplitStringAndTrim("=").ToArray();
                    if (items.Count() == 2)
                    {
                        cmd = items[0];
                        value = items[1];
                        return true;
                    }
                    else
                    {
                        value = null;
                        exception = new FormatException(string.Format("Argument '{0}' is not valid.", cmd));
                        return false;
                    }
                }

                // non equals syntax; the next term is the value if it is not proceeded with a dash
                if (cmd.EqualsCaseInsensitive(argument))
                {
                    // not all parameters have a value and some are the next word or group of words
                    if (i < args.Count)
                    {
                        try
                        {
                            value = args[i];
                            // this is not a value, but the next argument
                            if (value.StartsWith("-"))
                            {
                                value = null;
                            }
                        }
                        catch { }
                    }
                    return true;
                }
            }
            return false;
        }
    }
}
