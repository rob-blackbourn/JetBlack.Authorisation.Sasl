namespace JetBlack.Authorisation.Sasl.Mechanism.Plain
{
    /// <summary>
    /// RFC 4616.2. PLAIN SASL Mechanism.
    /// 
    /// The mechanism consists of a single message, a string of [UTF-8]
    /// encoded [Unicode] characters, from the client to the server.  The
    /// client presents the authorization identity (identity to act as),
    /// followed by a NUL (U+0000) character, followed by the authentication
    /// identity (identity whose password will be used), followed by a NUL
    /// (U+0000) character, followed by the clear-text password.  As with
    /// other SASL mechanisms, the client does not provide an authorization
    /// identity when it wishes the server to derive an identity from the
    /// credentials and use that as the authorization identity.
    /// 
    /// message   = [authzid] UTF8NUL authcid UTF8NUL passwd
    /// 
    /// Example:
    ///     C: a002 AUTHENTICATE "PLAIN"
    ///     S: + ""
    ///     C: {21}
    ///     C: &lt;NUL&gt;tim&lt;NUL&gt;tanstaaftanstaaf
    ///     S: a002 OK "Authenticated"
    /// </summary>
    public abstract class PlainSaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "PLAIN"; }
        }
    }
}
