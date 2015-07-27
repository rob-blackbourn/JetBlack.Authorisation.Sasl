using System;

namespace JetBlack.Authorisation.Utils
{
    /// <summary>
    /// This exception is thrown when parse errors are encountered.
    /// </summary>
    public class ParseException : Exception
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="message"></param>
        public ParseException(string message) : base(message)
        {
        }
    }
}
