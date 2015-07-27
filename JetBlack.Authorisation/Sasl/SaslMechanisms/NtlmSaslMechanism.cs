namespace JetBlack.Authorisation.Sasl.SaslMechanisms
{
    public abstract class NtlmSaslMechanism : ISaslMechanism
    {
        /// <summary>
        /// Returns always "NTLM".
        /// </summary>
        public string Name
        {
            get { return "NTLM"; }
        }
    }
}
