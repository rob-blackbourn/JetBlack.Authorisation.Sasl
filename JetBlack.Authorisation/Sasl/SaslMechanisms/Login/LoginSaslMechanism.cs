namespace JetBlack.Authorisation.Sasl.SaslMechanisms.Login
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
