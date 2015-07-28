namespace JetBlack.Authorisation.Sasl.Mechanism.XoAuth
{
    public abstract class XoAuthSaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "XOAUTH"; }
        }
    }
}
