namespace JetBlack.Authorisation.Sasl.SaslMechanisms
{
    public abstract class PlainSaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "PLAIN"; }
        }
    }
}
