namespace JetBlack.Authorisation.Sasl.SaslMechanisms.CramMd5
{
    public class CramMd5SaslMechanism : ISaslMechanism
    {
        /// <summary>
        /// Returns always "LOGIN".
        /// </summary>
        public string Name
        {
            get { return "CRAM-MD5"; }
        }
    }
}
