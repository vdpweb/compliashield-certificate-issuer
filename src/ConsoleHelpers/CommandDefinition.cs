

namespace ConsoleHelpers
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    public class CommandDefintion
    {
        public string CommandName { get; set; }

        private Dictionary<string, ParameterDefinition> _parameters;

        public IReadOnlyDictionary<string, ParameterDefinition> Parameters { get { return _parameters; } }

        public CommandDefintion()
        {
            _parameters = new Dictionary<string, ParameterDefinition>(StringComparer.OrdinalIgnoreCase);
        }

        public void SetParameterDefinition(string parameterName, bool argumentIsRequired)
        {
            this.SetParameterDefinition(parameterName, argumentIsRequired, null, null);
        }

        public void SetParameterDefinition(string parameterName, bool argumentIsRequired, string helpText)
        {
            this.SetParameterDefinition(parameterName, argumentIsRequired, null, null, helpText);
        }

        public void SetParameterDefinition(string parameterName, bool argumentIsRequired, string argumentRegExMatchPattern, string argumentRegExErrorMessage)
        {
            SetParameterDefinition(parameterName, argumentIsRequired, argumentRegExMatchPattern, argumentRegExErrorMessage, null);
        }

        public void SetParameterDefinition(string parameterName, bool argumentIsRequired, string argumentRegExMatchPattern, string argumentRegExErrorMessage, string helpText)
        {
            if (string.IsNullOrEmpty(parameterName))
            {
                throw new ArgumentException("parameterName");
            }
            if (!string.IsNullOrEmpty(argumentRegExMatchPattern) && !RegExPatterns.IsValidRegex(argumentRegExMatchPattern))
            {
                throw new ArgumentException("argumentRegExMatchPattern is not a valid RegEx pattern");
            }
            parameterName = parameterName.ToLower();
            _parameters[parameterName] = new ParameterDefinition() { ParameterName = parameterName, ArgumentIsRequired = argumentIsRequired, ArgumentRegExMatchPattern = argumentRegExMatchPattern, ArgumentRegExErrorMessage = argumentRegExErrorMessage, HelpText = helpText };
        }

        public void RemoveParmeter(string parameterName)
        {
            if (string.IsNullOrEmpty(parameterName))
            {
                throw new ArgumentException("parameterName");
            }
            parameterName = parameterName.ToLower();
            if (_parameters.ContainsKey(parameterName))
            {
                _parameters.Remove(parameterName);
            }
        }
    }
    
    public struct ParameterDefinition
    {
        public string ParameterName;

        public bool ArgumentIsRequired;

        public string ArgumentRegExMatchPattern;

        public string ArgumentRegExErrorMessage;

        public string HelpText;
    }
}
