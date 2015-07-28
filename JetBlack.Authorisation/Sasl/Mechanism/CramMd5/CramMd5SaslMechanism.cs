namespace JetBlack.Authorisation.Sasl.Mechanism.CramMd5
{
    /// <summary>
    /// Implements "CRAM-MD5" authenticaiton.
    /// 
    /// RFC 2195 2. Challenge-Response Authentication Mechanism.
    /// The authentication type associated with CRAM is "CRAM-MD5".
    ///
    /// The data encoded in the first ready response contains an
    /// presumptively arbitrary string of random digits, a timestamp, and the
    /// fully-qualified primary host name of the server.The syntax of the
    /// unencoded form must correspond to that of an RFC 822 'msg-id'
    /// [RFC822] as described in [POP3].
    /// 
    /// The client makes note of the data and then responds with a string
    /// consisting of the user name, a space, and a 'digest'.  The latter is
    /// computed by applying the keyed MD5 algorithm from[KEYED - MD5] where
    /// the key is a shared secret and the digested text is the timestamp
    /// (including angle-brackets).
    /// 
    /// This shared secret is a string known only to the client and server.
    /// The `digest' parameter itself is a 16-octet value which is sent in
    /// hexadecimal format, using lower-case ASCII characters.
    /// 
    /// When the server receives this client response, it verifies the digest
    /// provided.If the digest is correct, the server should consider the
    /// client authenticated and respond appropriately.
    /// 
    /// Example:
    ///     The examples in this document show the use of the CRAM mechanism with
    ///     the IMAP4 AUTHENTICATE command[IMAP - AUTH].  The base64 encoding of
    ///     the challenges and responses is part of the IMAP4 AUTHENTICATE
    ///     command, not part of the CRAM specification itself.
    /// 
    ///     S: * OK IMAP4 Server
    ///     C: A0001 AUTHENTICATE CRAM-MD5
    ///     S: + PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+
    ///     C: dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw
    ///     S: A0001 OK CRAM authentication successful
    /// 
    ///    In this example, the shared secret is the string
    ///    'tanstaaftanstaaf'.  Hence, the Keyed MD5 digest is produced by
    ///    calculating
    /// 
    ///    MD5((tanstaaftanstaaf XOR opad), MD5((tanstaaftanstaaf XOR ipad), &lt;1896.697170952@postoffice.reston.mci.net&gt;))
    /// 
    ///    where ipad and opad are as defined in the keyed-MD5 Work in
    ///    Progress[KEYED - MD5] and the string shown in the challenge is the
    ///    base64 encoding of &lt;1896.697170952@postoffice.reston.mci.net&gt;. The
    ///    shared secret is null-padded to a length of 64 bytes.If the
    ///    shared secret is longer than 64 bytes, the MD5 digest of the
    ///    shared secret is used as a 16 byte input to the keyed MD5
    ///    calculation.
    /// 
    ///    This produces a digest value (in hexadecimal) of
    ///        b913a602c7eda7a495b4e6e7334d3890
    /// 
    ///    The user name is then prepended to it, forming
    ///    tim b913a602c7eda7a495b4e6e7334d3890
    ///    Which is then base64 encoded to meet the requirements of the IMAP4
    ///    AUTHENTICATE command(or the similar POP3 AUTH command), yielding
    ///    dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw
    /// </summary>
    public class CramMd5SaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "CRAM-MD5"; }
        }
    }
}
