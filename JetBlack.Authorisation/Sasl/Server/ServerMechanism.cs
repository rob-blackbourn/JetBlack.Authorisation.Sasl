﻿using System.Collections.Generic;

namespace JetBlack.Authorisation.Sasl.Server
{
    /// <summary>
    /// This base class for server SASL authentication mechanisms.
    /// </summary>
    public abstract class ServerMechanism
    {
        private Dictionary<string, object> _tags = null;

        /// <summary>
        /// Resets any authentication state data.
        /// </summary>
        public abstract void Reset();

        /// <summary>
        /// Continues authentication process.
        /// </summary>
        /// <param name="clientResponse">Client sent SASL response.</param>
        /// <returns>Retunrns challange response what must be sent to client or null if authentication has completed.</returns>
        /// <exception cref="ArgumentNullException">Is raised when <b>clientRespone</b> is null reference.</exception>
        public abstract byte[] Continue(byte[] clientResponse);

        /// <summary>
        /// Gets if the authentication exchange has completed.
        /// </summary>
        public abstract bool IsCompleted { get; }

        /// <summary>
        /// Gets if user has authenticated sucessfully.
        /// </summary>
        public abstract bool IsAuthenticated { get; }

        /// <summary>
        /// Gets IANA-registered SASL authentication mechanism name.
        /// </summary>
        /// <remarks>The registered list is available from: http://www.iana.org/assignments/sasl-mechanisms .</remarks>
        public abstract string Name { get; }

        /// <summary>
        /// Gets if specified SASL mechanism is available only to SSL connection.
        /// </summary>
        public abstract bool RequireSSL { get; }

        /// <summary>
        /// Gets user login name.
        /// </summary>
        public abstract string UserName { get; }

        /// <summary>
        /// Gets user data items collection.
        /// </summary>
        /// <exception cref="ObjectDisposedException">Is raised when this object is disposed and this property is accessed.</exception>
        public Dictionary<string, object> Tags
        {
            get { return _tags; }
        }
    }
}