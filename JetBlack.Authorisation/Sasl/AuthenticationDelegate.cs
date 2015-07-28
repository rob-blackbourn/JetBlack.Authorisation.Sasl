namespace JetBlack.Authorisation.Sasl
{
    public delegate bool AuthenticationDelegate(string authorizationId, string username, string password);
}
