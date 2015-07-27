namespace JetBlack.Authorisation.Sasl.SaslMechanisms
{
    public abstract class XoAuthSaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "XOAUTH"; }
        }
    }
}
