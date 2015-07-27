using JetBlack.Authorisation.Utils;
using System;
using System.Text;

namespace JetBlack.Authorisation
{
    /// <summary>
    /// This class represents SASL DIGEST-MD5 authentication <b>digest-challenge</b>. Defined in RFC 2831.
    /// </summary>
    public class DigestMd5Challenge
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="realm">Realm value.</param>
        /// <param name="nonce">Nonce value.</param>
        /// <param name="qopOptions">Quality of protections supported. Normally this is "auth".</param>
        /// <param name="isStale">Stale value.</param>
        /// <exception cref="ArgumentNullException">Is raised when <b>realm</b>,<b>nonce</b> or <b>qopOptions</b> is null reference.</exception>
        public DigestMd5Challenge(string[] realm, string nonce, string[] qopOptions, bool isStale)
        {
            if (realm == null)
                throw new ArgumentNullException("realm");
            if (nonce == null)
                throw new ArgumentNullException("nonce");
            if (qopOptions == null)
                throw new ArgumentNullException("qopOptions");

            Realm = realm;
            Nonce = nonce;
            QopOptions = qopOptions;
            IsStale = isStale;
            Charset = "utf-8";
            Algorithm = "md5-sess";
        }

        /// <summary>
        /// Internal parse constructor.
        /// </summary>
        private DigestMd5Challenge()
        {
        }

        /// <summary>
        /// Parses DIGEST-MD5 challenge from challenge-string.
        /// </summary>
        /// <param name="challenge">Challenge string.</param>
        /// <returns>Returns DIGEST-MD5 challenge.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>challenge</b> is null reference.</exception>
        /// <exception cref="ParseException">Is raised when challenge parsing + validation fails.</exception>
        public static DigestMd5Challenge Parse(string challenge)
        {
            if (challenge == null)
                throw new ArgumentNullException("challenge");

            var retVal = new DigestMd5Challenge();

            var parameters = TextUtils.SplitQuotedString(challenge, ',');
            foreach (var parameter in parameters)
            {
                var nameValue = parameter.Split(new[] { '=' }, 2);
                var name = nameValue[0].Trim();

                if (nameValue.Length == 2)
                {
                    if (name.ToLower() == "realm")
                    {
                        retVal.Realm = TextUtils.UnQuoteString(nameValue[1]).Split(',');
                    }
                    else if (name.ToLower() == "nonce")
                    {
                        retVal.Nonce = TextUtils.UnQuoteString(nameValue[1]);
                    }
                    else if (name.ToLower() == "qop")
                    {
                        retVal.QopOptions = TextUtils.UnQuoteString(nameValue[1]).Split(',');
                    }
                    else if (name.ToLower() == "stale")
                    {
                        retVal.IsStale = Convert.ToBoolean(TextUtils.UnQuoteString(nameValue[1]));
                    }
                    else if (name.ToLower() == "maxbuf")
                    {
                        retVal.Maxbuf = Convert.ToInt32(TextUtils.UnQuoteString(nameValue[1]));
                    }
                    else if (name.ToLower() == "charset")
                    {
                        retVal.Charset = TextUtils.UnQuoteString(nameValue[1]);
                    }
                    else if (name.ToLower() == "algorithm")
                    {
                        retVal.Algorithm = TextUtils.UnQuoteString(nameValue[1]);
                    }
                    else if (name.ToLower() == "cipher-opts")
                    {
                        retVal.CipherOpts = TextUtils.UnQuoteString(nameValue[1]);
                    }
                    //else if(name.ToLower() == "auth-param"){
                    //    retVal.m_AuthParam = TextUtils.UnQuoteString(name_value[1]);
                    //}
                }
            }

            /* Validate required fields.
                Per RFC 2831 2.1.1. Only [nonce algorithm] parameters are required.
            */
            if (string.IsNullOrEmpty(retVal.Nonce))
            {
                throw new ParseException("The challenge-string doesn't contain required parameter 'nonce' value.");
            }
            if (string.IsNullOrEmpty(retVal.Algorithm))
            {
                throw new ParseException("The challenge-string doesn't contain required parameter 'algorithm' value.");
            }

            return retVal;
        }

        /// <summary>
        /// Returns DIGEST-MD5 "digest-challenge" string.
        /// </summary>
        /// <returns>
        /// Returns DIGEST-MD5 "digest-challenge" string.
        /// </returns>
        /// <remarks>
        /// RFC 2831 2.1.1.
        /// The server starts by sending a challenge. The data encoded in the
        /// challenge contains a string formatted according to the rules for a
        /// "digest-challenge" defined as follows:
        /// 
        /// digest-challenge  =
        ///                     1#( realm | nonce | qop-options | stale | maxbuf | charset
        ///                         algorithm | cipher-opts | auth-param )
        /// 
        /// realm             = "realm" "=" <"> realm-value <">
        /// realm-value       = qdstr-val
        /// nonce             = "nonce" "=" <"> nonce-value <">
        /// nonce-value       = qdstr-val
        /// qop-options       = "qop" "=" <"> qop-list <">
        /// qop-list          = 1#qop-value
        /// qop-value         = "auth" | "auth-int" | "auth-conf" | token
        /// stale             = "stale" "=" "true"
        /// maxbuf            = "maxbuf" "=" maxbuf-value
        /// maxbuf-value      = 1*DIGIT
        /// charset           = "charset" "=" "utf-8"
        /// algorithm         = "algorithm" "=" "md5-sess"
        /// cipher-opts       = "cipher" "=" <"> 1#cipher-value <">
        /// cipher-value      = "3des" | "des" | "rc4-40" | "rc4" | "rc4-56" | token
        /// auth-param        = token "=" ( token | quoted-string )
        /// </remarks>
        public string ToChallenge()
        {
            var retVal = new StringBuilder();
            retVal.Append("realm=\"" + Net_Utils.ArrayToString(Realm, ",") + "\"");
            retVal.Append(",nonce=\"" + Nonce + "\"");
            if (QopOptions != null)
                retVal.Append(",qop=\"" + Net_Utils.ArrayToString(QopOptions, ",") + "\"");
            if (IsStale)
                retVal.Append(",stale=true");
            if (Maxbuf > 0)
                retVal.Append(",maxbuf=" + Maxbuf);
            if (!string.IsNullOrEmpty(Charset))
                retVal.Append(",charset=" + Charset);
            retVal.Append(",algorithm=" + Algorithm);
            if (!string.IsNullOrEmpty(CipherOpts))
                retVal.Append(",cipher-opts=\"" + CipherOpts + "\"");
            //if(!string.IsNullOrEmpty(this.AuthParam)){
            //    retVal.Append("auth-param=\"" + this.AuthParam + "\"");
            //}

            return retVal.ToString();
        }

        /// <summary>
        /// Gets realm value. For more info see RFC 2831.
        /// </summary>
        public string[] Realm { get; private set; }

        /// <summary>
        /// Gets nonce value. For more info see RFC 2831.
        /// </summary>
        public string Nonce { get; private set; }

        /// <summary>
        /// Gets qop-options value. For more info see RFC 2831.
        /// </summary>
        public string[] QopOptions { get; private set; }

        /// <summary>
        /// Gets if stale value. For more info see RFC 2831.
        /// </summary>
        public bool IsStale { get; private set; }

        /// <summary>
        /// Gets maxbuf value. For more info see RFC 2831.
        /// </summary>
        public int Maxbuf { get; private set; }

        /// <summary>
        /// Gets charset value. For more info see RFC 2831.
        /// </summary>
        public string Charset { get; private set; }

        /// <summary>
        /// Gets algorithm value. For more info see RFC 2831.
        /// </summary>
        public string Algorithm { get; private set; }

        /// <summary>
        /// Gets cipher-opts value. For more info see RFC 2831.
        /// </summary>
        public string CipherOpts { get; private set; }
    }
}
