namespace JetBlack.Authorisation.Sasl.SaslMechanisms
{
    public abstract class LoginSaslMechanism : ISaslMechanism
    {
        /// <summary>
        /// Returns always "LOGIN".
        /// </summary>
        public string Name
        {
            get { return "LOGIN"; }
        }
    }
}
