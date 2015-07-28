namespace JetBlack.Authorisation.Sasl.Mechanism.XoAuth2
{
    public abstract class XoAuth2SaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "XOAUTH2"; }
        }
    }
}
