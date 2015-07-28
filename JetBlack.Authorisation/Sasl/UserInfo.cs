namespace JetBlack.Authorisation.Sasl
{
    public struct UserInfo
    {
        public UserInfo(bool userExists, string userName, string password)
            : this()
        {
            UserExists = userExists;
            UserName = userName;
            Password = password;
        }

        public bool UserExists { get; private set; }
        public string UserName { get; private set; }
        public string Password { get; private set; }
    }
}
