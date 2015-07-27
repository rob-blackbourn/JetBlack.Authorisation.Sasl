namespace JetBlack.Authorisation.Sasl.SaslMechanisms
{
    public abstract class DigestMd5SaslMechanism : ISaslMechanism
    {
        /// <summary>
        /// Returns always "DIGEST-MD5".
        /// </summary>
        public string Name
        {
            get { return "DIGEST-MD5"; }
        }
    }
}
