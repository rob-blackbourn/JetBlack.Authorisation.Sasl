namespace JetBlack.Authorisation.Sasl.Mechanism.Ntlm
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
