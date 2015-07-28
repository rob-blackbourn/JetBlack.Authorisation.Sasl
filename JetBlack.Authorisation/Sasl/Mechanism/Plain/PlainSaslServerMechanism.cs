using System;
using System.Collections.Generic;
using System.Text;
using JetBlack.Authorisation.Utils;

namespace JetBlack.Authorisation.Sasl.Mechanism.Plain
{
    /// <summary>
    /// Implements "PLAIN" authenticaiton. Defined in RFC 4616.
    /// </summary>
    public class PlainSaslServerMechanism : PlainSaslMechanism, ISaslServerMechanism
    {
        private readonly AuthenticationDelegate _authenticationDelegate;

        /// <summary>
        /// PLan server mechanism Constructor.
        /// </summary>
        /// <param name="authenticationDelegate">Function called to authenticate user.</param>
        public PlainSaslServerMechanism(AuthenticationDelegate authenticationDelegate)
        {
            if (authenticationDelegate == null)
                throw new ArgumentNullException("authenticationDelegate");

            _authenticationDelegate = authenticationDelegate;
        }

        /// <summary>
        /// Resets any authentication state data.
        /// </summary>
        public void Reset()
        {
            IsCompleted = false;
            IsAuthenticated = false;
            UserName = string.Empty;
        }

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="clientResponse">Client sent SASL response.</param>
        /// <returns>Retunrns challange response what must be sent to client or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>clientResponse</b> is null reference.</exception>
        /// <remarks>
        /// RFC 4616.2. PLAIN SASL Mechanism.                
        /// The mechanism consists of a single message, a string of[UTF - 8]
        /// encoded[Unicode] characters, from the client to the server.The
        /// client presents the authorization identity(identity to act as),
        /// followed by a NUL(U+0000) character, followed by the authentication
        /// identity(identity whose password will be used), followed by a NUL
        /// (U+0000) character, followed by the clear-text password.As with
        /// other SASL mechanisms, the client does not provide an authorization
        /// identity when it wishes the server to derive an identity from the
        /// credentials and use that as the authorization identity.
        ///
        /// message   = [authzid] UTF8NUL authcid UTF8NUL passwd
        ///
        /// Example:
        ///     C: a002 AUTHENTICATE "PLAIN"
        ///     S: + ""
        ///     C: { 21}
        ///     C: &lt;NUL&gt;tim&lt;NUL&gt;tanstaaftanstaaf
        ///     S: a002 OK "Authenticated"
        /// </remarks>
        public byte[] Continue(byte[] clientResponse)
        {
            if (clientResponse == null)
                throw new ArgumentNullException("clientResponse");

            if (clientResponse.Length == 0)
                return new byte[0];

            var parts = Encoding.UTF8.GetString(clientResponse).Split('\0');
            if (parts.Length == 3 && !string.IsNullOrEmpty(parts[1]))
            {
                AuthorizationId = parts[0].NullIfWhitespace();
                UserName = parts[1];
                IsAuthenticated = _authenticationDelegate(AuthorizationId, UserName, parts[2].NullIfWhitespace());
            }

            IsCompleted = true;

            return null;
        }

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        public bool IsCompleted { get; private set; }

        /// <summary>
        /// Gets if user has authenticated sucessfully.
        /// </summary>
        public bool IsAuthenticated { get; private set; }

        public string AuthorizationId { get; private set; }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        public string UserName { get; private set; }

        public Dictionary<string, object> Tags
        {
            get { return null; }
        }
    }
}
