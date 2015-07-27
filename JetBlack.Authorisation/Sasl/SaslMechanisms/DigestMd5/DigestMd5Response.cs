using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using JetBlack.Authorisation.Utils;

namespace JetBlack.Authorisation.Sasl.SaslMechanisms.DigestMd5
{
    /// <summary>
    /// This class represents SASL DIGEST-MD5 authentication <b>digest-response</b>. Defined in RFC 2831.
    /// </summary>
    public class DigestMd5Response
    {
        private string _password = null;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="challenge">Client challenge.</param>
        /// <param name="realm">Realm value. This must be one value of the challenge Realm.</param>
        /// <param name="userName">User name.</param>
        /// <param name="password">User password.</param>
        /// <param name="cnonce">Client nonce value.</param>
        /// <param name="nonceCount">Nonce count. One-based client authentication attempt number. Normally this value is 1.</param>
        /// <param name="qop">Indicates what "quality of protection" the client accepted. This must be one value of the challenge QopOptions.</param>
        /// <param name="digestUri">Digest URI.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>challenge</b>,<b>realm</b>,<b>password</b>,<b>nonce</b>,<b>qop</b> or <b>digestUri</b> is null reference.</exception>
        public DigestMd5Response(DigestMd5Challenge challenge, string realm, string userName, string password, string cnonce, int nonceCount, string qop, string digestUri)
        {
            Cnonce = null;
            NonceCount = 0;
            Qop = null;
            Authzid = null;
            Cipher = null;
            Charset = null;
            Response = null;
            DigestUri = null;
            Nonce = null;
            Realm = null;
            UserName = null;
            if (challenge == null)
                throw new ArgumentNullException("challenge");
            if (realm == null)
                throw new ArgumentNullException("realm");
            if (userName == null)
                throw new ArgumentNullException("userName");
            if (password == null)
                throw new ArgumentNullException("password");
            if (cnonce == null)
                throw new ArgumentNullException("cnonce");
            if (qop == null)
                throw new ArgumentNullException("qop");
            if (digestUri == null)
                throw new ArgumentNullException("digestUri");

            Realm = realm;
            UserName = userName;
            _password = password;
            Nonce = challenge.Nonce;
            Cnonce = cnonce;
            NonceCount = nonceCount;
            Qop = qop;
            DigestUri = digestUri;
            Response = CalculateResponse(userName, password);
            Charset = challenge.Charset;
        }

        /// <summary>
        /// Internal parse constructor.
        /// </summary>
        private DigestMd5Response()
        {
            Cnonce = null;
            NonceCount = 0;
            Qop = null;
            Authzid = null;
            Cipher = null;
            Charset = null;
            Response = null;
            DigestUri = null;
            Nonce = null;
            Realm = null;
            UserName = null;
        }

        /// <summary>
        /// Parses DIGEST-MD5 response from response-string.
        /// </summary>
        /// <param name="digestResponse">Response string.</param>
        /// <returns>Returns DIGEST-MD5 response.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>digestResponse</b> isnull reference.</exception>
        /// <exception cref="ParseException">Is raised when response parsing + validation fails.</exception>
        public static DigestMd5Response Parse(string digestResponse)
        {
            if (digestResponse == null)
                throw new ArgumentNullException("digestResponse");

            /* RFC 2831 2.1.2.
                The client makes note of the "digest-challenge" and then responds
                with a string formatted and computed according to the rules for a
                "digest-response" defined as follows:

                digest-response  = 1#( username | realm | nonce | cnonce |
                                       nonce-count | qop | digest-uri | response |
                                       maxbuf | charset | cipher | authzid |
                                       auth-param )

                username         = "username" "=" <"> username-value <">
                username-value   = qdstr-val
                cnonce           = "cnonce" "=" <"> cnonce-value <">
                cnonce-value     = qdstr-val
                nonce-count      = "nc" "=" nc-value
                nc-value         = 8LHEX
                qop              = "qop" "=" qop-value
                digest-uri       = "digest-uri" "=" <"> digest-uri-value <">
                digest-uri-value  = serv-type "/" host [ "/" serv-name ]
                serv-type        = 1*ALPHA
                host             = 1*( ALPHA | DIGIT | "-" | "." )
                serv-name        = host
                response         = "response" "=" response-value
                response-value   = 32LHEX
                LHEX             = "0" | "1" | "2" | "3" |
                                   "4" | "5" | "6" | "7" |
                                   "8" | "9" | "a" | "b" |
                                   "c" | "d" | "e" | "f"
                cipher           = "cipher" "=" cipher-value
                authzid          = "authzid" "=" <"> authzid-value <">
                authzid-value    = qdstr-val
            */

            var retVal = new DigestMd5Response
            {
                Realm = "" // Set default values.
            };

            var parameters = TextUtils.SplitQuotedString(digestResponse, ',');
            foreach (var parameter in parameters.Select(ToKeyValuePair).Where(x => !Equals(x, default(KeyValuePair<string,string>))))
            {
                switch (parameter.Key.ToLower())
                {
                    case "username":
                        retVal.UserName = TextUtils.UnQuoteString(parameter.Value);
                        break;
                    case "realm":
                        retVal.Realm = TextUtils.UnQuoteString(parameter.Value);
                        break;
                    case "nonce":
                        retVal.Nonce = TextUtils.UnQuoteString(parameter.Value);
                        break;
                    case "cnonce":
                        retVal.Cnonce = TextUtils.UnQuoteString(parameter.Value);
                        break;
                    case "nc":
                        retVal.NonceCount = Int32.Parse(TextUtils.UnQuoteString(parameter.Value), NumberStyles.HexNumber);
                        break;
                    case "qop":
                        retVal.Qop = TextUtils.UnQuoteString(parameter.Value);
                        break;
                    case "digest-uri":
                        retVal.DigestUri = TextUtils.UnQuoteString(parameter.Value);
                        break;
                    case "response":
                        retVal.Response = TextUtils.UnQuoteString(parameter.Value);
                        break;
                    case "charset":
                        retVal.Charset = TextUtils.UnQuoteString(parameter.Value);
                        break;
                    case "cipher":
                        retVal.Cipher = TextUtils.UnQuoteString(parameter.Value);
                        break;
                    case "authzid":
                        retVal.Authzid = TextUtils.UnQuoteString(parameter.Value);
                        break;
                }
            }

            /* Validate required fields.
                Per RFC 2831 2.1.2. Only [username nonce cnonce nc response] parameters are required.
            */
            if (string.IsNullOrEmpty(retVal.UserName))
                throw new ParseException("The response-string doesn't contain required parameter 'username' value.");
            if (string.IsNullOrEmpty(retVal.Nonce))
                throw new ParseException("The response-string doesn't contain required parameter 'nonce' value.");
            if (string.IsNullOrEmpty(retVal.Cnonce))
                throw new ParseException("The response-string doesn't contain required parameter 'cnonce' value.");
            if (retVal.NonceCount < 1)
                throw new ParseException("The response-string doesn't contain required parameter 'nc' value.");
            if (string.IsNullOrEmpty(retVal.Response))
                throw new ParseException("The response-string doesn't contain required parameter 'response' value.");

            return retVal;
        }

        private static KeyValuePair<string, string> ToKeyValuePair(string parameter)
        {
            var nameValue = parameter.Split(new[] { '=' }, 2);
            return
                nameValue.Length == 2
                    ? new KeyValuePair<string, string>(nameValue[0].Trim(), nameValue[1])
                    : default(KeyValuePair<string, string>);
        }

        /// <summary>
        /// Authenticates user.
        /// </summary>
        /// <param name="userName">User name.</param>
        /// <param name="password">Password.</param>
        /// <returns>Returns true if user authenticated, otherwise false.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>userName</b> or <b>password</b> is null reference.</exception>
        public bool Authenticate(string userName, string password)
        {
            if (userName == null)
                throw new ArgumentNullException("userName");
            if (password == null)
                throw new ArgumentNullException("password");

            return Response == CalculateResponse(userName, password);
        }

        /// <summary>
        /// Creates digest response for challenge.
        /// </summary>
        /// <returns>Returns digest response.</returns>
        public string ToResponse()
        {
            /* RFC 2831 2.1.2.
                The client makes note of the "digest-challenge" and then responds
                with a string formatted and computed according to the rules for a
                "digest-response" defined as follows:

                digest-response  = 1#( username | realm | nonce | cnonce |
                                       nonce-count | qop | digest-uri | response |
                                       maxbuf | charset | cipher | authzid |
                                       auth-param )

                username         = "username" "=" <"> username-value <">
                username-value   = qdstr-val
                cnonce           = "cnonce" "=" <"> cnonce-value <">
                cnonce-value     = qdstr-val
                nonce-count      = "nc" "=" nc-value
                nc-value         = 8LHEX
                qop              = "qop" "=" qop-value
                digest-uri       = "digest-uri" "=" <"> digest-uri-value <">
                digest-uri-value  = serv-type "/" host [ "/" serv-name ]
                serv-type        = 1*ALPHA
                host             = 1*( ALPHA | DIGIT | "-" | "." )
                serv-name        = host
                response         = "response" "=" response-value
                response-value   = 32LHEX
                LHEX             = "0" | "1" | "2" | "3" |
                                   "4" | "5" | "6" | "7" |
                                   "8" | "9" | "a" | "b" |
                                   "c" | "d" | "e" | "f"
                cipher           = "cipher" "=" cipher-value
                authzid          = "authzid" "=" <"> authzid-value <">
                authzid-value    = qdstr-val
            */

            var retVal = new StringBuilder();
            retVal.Append("username=\"" + UserName + "\"");
            retVal.Append(",realm=\"" + Realm + "\"");
            retVal.Append(",nonce=\"" + Nonce + "\"");
            retVal.Append(",cnonce=\"" + Cnonce + "\"");
            retVal.Append(",nc=" + NonceCount.ToString("x8"));
            retVal.Append(",qop=" + Qop);
            retVal.Append(",digest-uri=\"" + DigestUri + "\"");
            retVal.Append(",response=" + Response);
            if (!string.IsNullOrEmpty(Charset))
                retVal.Append(",charset=" + Charset);
            if (!string.IsNullOrEmpty(Cipher))
                retVal.Append(",cipher=\"" + Cipher + "\"");
            if (!string.IsNullOrEmpty(Authzid))
                retVal.Append(",authzid=\"" + Authzid + "\"");
            // auth-param

            return retVal.ToString();
        }

        /// <summary>
        /// Creates <b>response-auth</b> response for client.
        /// </summary>
        /// <returns>Returns <b>response-auth</b> response.</returns>
        public string ToRspauthResponse(string userName, string password)
        {
            /* RFC 2831 2.1.3.
                The server receives and validates the "digest-response". The server
                checks that the nonce-count is "00000001". If it supports subsequent
                authentication (see section 2.2), it saves the value of the nonce and
                the nonce-count. It sends a message formatted as follows:

                    response-auth = "rspauth" "=" response-value

                where response-value is calculated as above, using the values sent in
                step two, except that if qop is "auth", then A2 is

                    A2 = { ":", digest-uri-value }

                And if qop is "auth-int" or "auth-conf" then A2 is

                    A2 = { ":", digest-uri-value, ":00000000000000000000000000000000" }

                Compared to its use in HTTP, the following Digest directives in the
                "digest-response" are unused:

                    nextnonce
                    qop
                    cnonce
                    nonce-count
             
                response-value  =
                    HEX( KD ( HEX(H(A1)),
                        { nonce-value, ":" nc-value, ":", cnonce-value, ":", qop-value, ":", HEX(H(A2)) }))
            */

            byte[] a2 = null;
            if (string.IsNullOrEmpty(Qop) || Qop.ToLower() == "auth")
                a2 = Encoding.UTF8.GetBytes(":" + DigestUri);
            else if (Qop.ToLower() == "auth-int" || Qop.ToLower() == "auth-conf")
                a2 = Encoding.UTF8.GetBytes(":" + DigestUri + ":00000000000000000000000000000000");

            if (Qop.ToLower() != "auth")
                throw new ArgumentException("Invalid 'qop' value '" + Qop + "'.");
            
            // RFC 2831 2.1.2.1.
            // response-value = HEX(KD(HEX(H(A1)),{nonce-value,":" nc-value,":",cnonce-value,":",qop-value,":",HEX(H(A2))}))
            return "rspauth=" + Hex(Kd(Hex(h(A1(userName, password))), Nonce + ":" + NonceCount.ToString("x8") + ":" + Cnonce + ":" + Qop + ":" + Hex(h(a2))));
        }

        /// <summary>
        /// Calculates digest response.
        /// </summary>
        /// <param name="userName">User name.</param>
        /// <param name="password">Password.</param>
        /// <returns>Returns digest response.</returns>
        private string CalculateResponse(string userName, string password)
        {
            /* RFC 2831.2.1.2.1.
                The definition of "response-value" above indicates the encoding for
                its value -- 32 lower case hex characters. The following definitions
                show how the value is computed.

                Although qop-value and components of digest-uri-value may be
                case-insensitive, the case which the client supplies in step two is
                preserved for the purpose of computing and verifying the
                response-value.

                response-value  =
                    HEX( KD ( HEX(H(A1)),
                        { nonce-value, ":" nc-value, ":", cnonce-value, ":", qop-value, ":", HEX(H(A2)) }))

                If authzid is specified, then A1 is

                    A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
                        ":", nonce-value, ":", cnonce-value, ":", authzid-value }

                If authzid is not specified, then A1 is

                    A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
                        ":", nonce-value, ":", cnonce-value }

                The "username-value", "realm-value" and "passwd" are encoded
                according to the value of the "charset" directive. If "charset=UTF-8"
                is present, and all the characters of either "username-value" or
                "passwd" are in the ISO 8859-1 character set, then it must be
                converted to ISO 8859-1 before being hashed. This is so that
                authentication databases that store the hashed username, realm and
                password (which is common) can be shared compatibly with HTTP, which
                specifies ISO 8859-1. A sample implementation of this conversion is
                in section 8.

                If the "qop" directive's value is "auth", then A2 is:

                    A2       = { "AUTHENTICATE:", digest-uri-value }

                If the "qop" value is "auth-int" or "auth-conf" then A2 is:

                    A2       = { "AUTHENTICATE:", digest-uri-value,
                                ":00000000000000000000000000000000" }

                Note that "AUTHENTICATE:" must be in upper case, and the second
                string constant is a string with a colon followed by 32 zeros.

                These apparently strange values of A2 are for compatibility with
                HTTP; they were arrived at by setting "Method" to "AUTHENTICATE" and
                the hash of the entity body to zero in the HTTP digest calculation of
                A2.

                Also, in the HTTP usage of Digest, several directives in the

                "digest-challenge" sent by the server have to be returned by the
                client in the "digest-response". These are:

                    opaque
                    algorithm

                These directives are not needed when Digest is used as a SASL
                mechanism (i.e., MUST NOT be sent, and MUST be ignored if received).
            */

            if (!string.IsNullOrEmpty(Qop) && Qop.ToLower() != "auth")
                throw new ArgumentException("Invalid 'qop' value '" + Qop + "'.");
            
            // RFC 2831 2.1.2.1.
            // response-value = HEX(KD(HEX(H(A1)),{nonce-value,":" nc-value,":",cnonce-value,":",qop-value,":",HEX(H(A2))}))
            return Hex(Kd(Hex(h(A1(userName, password))), Nonce + ":" + NonceCount.ToString("x8") + ":" + Cnonce + ":" + Qop + ":" + Hex(h(A2()))));
        }

        /// <summary>
        /// Calculates A1 value.
        /// </summary>
        /// <param name="userName">User name.</param>
        /// <param name="password">Password.</param>
        /// <returns>Returns A1 value.</returns>
        private byte[] A1(string userName, string password)
        {
            /* RFC 2831 2.1.2.1.
                If authzid is specified, then A1 is

                A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
                      ":", nonce-value, ":", cnonce-value, ":", authzid-value }

                If authzid is not specified, then A1 is

                A1 = { H( { username-value, ":", realm-value, ":", passwd } ),
                      ":", nonce-value, ":", cnonce-value
             
                NOTE: HTTP MD5 RFC 2617 supports more algorithms. SASL requires md5-sess.
            */

            if (string.IsNullOrEmpty(Authzid))
            {
                var userRealmPwd = h(Encoding.UTF8.GetBytes(userName + ":" + Realm + ":" + password));
                var nonceCnonce = Encoding.UTF8.GetBytes(":" + Nonce + ":" + Cnonce);

                var retVal = new byte[userRealmPwd.Length + nonceCnonce.Length];
                Array.Copy(userRealmPwd, 0, retVal, 0, userRealmPwd.Length);
                Array.Copy(nonceCnonce, 0, retVal, userRealmPwd.Length, nonceCnonce.Length);

                return retVal;
            }
            else
            {
                var userRealmPwd = h(Encoding.UTF8.GetBytes(userName + ":" + Realm + ":" + password));
                var nonceCnonceAuthzid = Encoding.UTF8.GetBytes(":" + Nonce + ":" + Cnonce + ":" + Authzid);

                var retVal = new byte[userRealmPwd.Length + nonceCnonceAuthzid.Length];
                Array.Copy(userRealmPwd, 0, retVal, 0, userRealmPwd.Length);
                Array.Copy(nonceCnonceAuthzid, 0, retVal, userRealmPwd.Length, nonceCnonceAuthzid.Length);

                return retVal;
            }
        }

        /// <summary>
        /// Calculates A2 value.
        /// </summary>
        /// <returns>Returns A2 value.</returns>
        private byte[] A2()
        {
            /* RFC 2831 2.1.2.1.
                If the "qop" directive's value is "auth", then A2 is:

                    A2       = { "AUTHENTICATE:", digest-uri-value }

                If the "qop" value is "auth-int" or "auth-conf" then A2 is:

                    A2       = { "AUTHENTICATE:", digest-uri-value, ":00000000000000000000000000000000" }

                Note that "AUTHENTICATE:" must be in upper case, and the second
                string constant is a string with a colon followed by 32 zeros.
             
                RFC 2617(HTTP MD5) 3.2.2.3.
                    A2       = Method ":" digest-uri-value ":" H(entity-body)

                NOTE: In SASL entity-body hash always "00000000000000000000000000000000".
            */

            if (string.IsNullOrEmpty(Qop) || Qop.ToLower() == "auth")
                return Encoding.UTF8.GetBytes("AUTHENTICATE:" + DigestUri);
            
            if (Qop.ToLower() == "auth-int" || Qop.ToLower() == "auth-conf")
                return Encoding.UTF8.GetBytes("AUTHENTICATE:" + DigestUri + ":00000000000000000000000000000000");
            
            throw new ArgumentException("Invalid 'qop' value '" + Qop + "'.");
        }

        /// <summary>
        /// Computes MD5 hash.
        /// </summary>
        /// <param name="value">Value to process.</param>
        /// <returns>Return MD5 hash.</returns>
        private byte[] h(byte[] value)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            return md5.ComputeHash(value);
        }

        private byte[] Kd(string secret, string data)
        {
            // KD(secret, data) = H(concat(secret, ":", data))
            return h(Encoding.UTF8.GetBytes(secret + ":" + data));
        }

        /// <summary>
        /// Converts value to hex string.
        /// </summary>
        /// <param name="value">Value to convert.</param>
        /// <returns>Returns hex string.</returns>
        private static string Hex(byte[] value)
        {
            return NetUtils.ToHex(value);
        }

        /// <summary>
        /// Gets user name.
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets realm(domain) name.
        /// </summary>
        public string Realm { get; private set; }

        /// <summary>
        /// Gets nonce value.
        /// </summary>
        public string Nonce { get; private set; }

        /// <summary>
        /// Gets cnonce value.
        /// </summary>
        public string Cnonce { get; private set; }

        /// <summary>
        /// Gets nonce count.
        /// </summary>
        public int NonceCount { get; private set; }

        /// <summary>
        /// Gets "quality of protection" value.
        /// </summary>
        public string Qop { get; private set; }

        /// <summary>
        /// Gets digest URI value.
        /// </summary>
        public string DigestUri { get; private set; }

        /// <summary>
        /// Gets response value.
        /// </summary>
        public string Response { get; private set; }

        /// <summary>
        /// Gets charset value.
        /// </summary>
        public string Charset { get; private set; }

        /// <summary>
        /// Gets cipher value.
        /// </summary>
        public string Cipher { get; private set; }

        /// <summary>
        /// Gets authorization ID.
        /// </summary>
        public string Authzid { get; private set; }
    }
}
