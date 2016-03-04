
namespace ConsoleHelpers
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;

    public static class Extensions
    {
        public static bool IsFullMatch(this string input, string regExPattern)
        {
            //if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(regExPattern))
            //{
            //    return false;
            //}
            Match match = Regex.Match(input, regExPattern);
            return ((match.Success && (match.Index == 0)) && (match.Length == input.Length));
        }

        public static IEnumerable<string> SplitStringAndTrim(this string helper, string splitCharacter)
        {
            //Get string coll of items
            string[] values = null;
            char splitOn = char.Parse(splitCharacter);
            values = helper.Split(new char[] { splitOn });
            var list = new List<string>();
            foreach (var s in values)
            {
                var thisVal = s.Trim();
                if (!string.IsNullOrWhiteSpace(thisVal))
                {
                    list.Add(thisVal);
                }
            }
            return list;
        }

        public static bool EqualsCaseInsensitive(this string helper, string compareTo)
        {
            return String.Equals(helper, compareTo, StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsValidEmailAddress(this string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return false;
            }
            Match match = Regex.Match(input, RegExPatterns.EmailAddress);
            return ((match.Success && (match.Index == 0)) && (match.Length == input.Length));
        }


    }
}
