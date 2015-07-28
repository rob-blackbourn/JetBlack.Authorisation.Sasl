namespace JetBlack.Authorisation.Sasl.Mechanism.Login
{
    /// <summary>
    /// RFC none.
    ///    S: "Username:"
    ///    C: userName
    ///    S: "Password:"
    ///    C: password
    ///
    /// NOTE: UserName may be included in initial client response.
    /// </summary>
    public abstract class LoginSaslMechanism : ISaslMechanism
    {
        public string Name
        {
            get { return "LOGIN"; }
        }
    }
}
