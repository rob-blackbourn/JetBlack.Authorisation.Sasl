namespace JetBlack.Authorisation.Sasl.SaslMechanisms.XoAuth
{
    public abstract class XoAuthSaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "XOAUTH"; }
        }
    }
}
