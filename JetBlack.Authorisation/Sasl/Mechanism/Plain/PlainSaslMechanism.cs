namespace JetBlack.Authorisation.Sasl.Mechanism.Plain
{
    public abstract class PlainSaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "PLAIN"; }
        }
    }
}
