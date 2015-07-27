using System;
using System.Collections.Generic;
using System.Linq;
using System.Timers;

namespace JetBlack.Authorisation.Sasl.SaslMechanisms.DigestMd5
{
    /// <summary>
    /// HTTP digest authentication nonce manager.
    /// </summary>
    public class HttpDigestNonceManager : IDisposable
    {
        /// <summary>
        /// This class represents nonce entry in active nonces collection.
        /// </summary>
        private class NonceEntry
        {
            /// <summary>
            /// Default constructor.
            /// </summary>
            /// <param name="nonce"></param>
            public NonceEntry(string nonce)
            {
                Nonce = nonce;
                CreateTime = DateTime.Now;
            }

            /// <summary>
            /// Gets nonce value.
            /// </summary>
            public string Nonce { get; private set; }

            /// <summary>
            /// Gets time when this nonce entry was created.
            /// </summary>
            public DateTime CreateTime { get; private set; }
        }

        private List<NonceEntry> _nonces;
        private int _expireTime = 30;
        private Timer _timer;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public HttpDigestNonceManager()
        {
            _nonces = new List<NonceEntry>();

            _timer = new Timer(15000);
            _timer.Elapsed += OnTimerElapsed;
            _timer.Enabled = true;
        }

        /// <summary>
        /// Cleans up nay resource being used.
        /// </summary>
        public void Dispose()
        {
            if (_nonces != null)
            {
                _nonces.Clear();
                _nonces = null;
            }

            if (_timer != null)
            {
                _timer.Dispose();
                _timer = null;
            }
        }

        private void OnTimerElapsed(object sender, ElapsedEventArgs e)
        {
            RemoveExpiredNonces();
        }

        /// <summary>
        /// Creates new nonce and adds it to active nonces collection.
        /// </summary>
        /// <returns>Returns new created nonce.</returns>
        public string CreateNonce()
        {
            var nonce = Guid.NewGuid().ToString().Replace("-", "");
            _nonces.Add(new NonceEntry(nonce));
            return nonce;
        }

        /// <summary>
        /// Checks if specified nonce exists in active nonces collection.
        /// </summary>
        /// <param name="nonce">Nonce to check.</param>
        /// <returns>Returns true if nonce exists in active nonces collection, otherwise returns false.</returns>
        public bool NonceExists(string nonce)
        {
            lock (_nonces)
            {
                return _nonces.Any(e => e.Nonce == nonce);
            }
        }

        /// <summary>
        /// Removes specified nonce from active nonces collection.
        /// </summary>
        /// <param name="nonce">Nonce to remove.</param>
        public void RemoveNonce(string nonce)
        {
            lock (_nonces)
            {
                for (var i = 0; i < _nonces.Count; ++i)
                {
                    if (_nonces[i].Nonce == nonce)
                        _nonces.RemoveAt(i--);
                }
            }
        }

        /// <summary>
        /// Removes not used nonces what has expired.
        /// </summary>
        private void RemoveExpiredNonces()
        {
            lock (_nonces)
            {
                for (var i = 0; i < _nonces.Count; ++i)
                {
                    // Nonce expired, remove it.
                    if (_nonces[i].CreateTime.AddSeconds(_expireTime) < DateTime.Now)
                        _nonces.RemoveAt(i--);
                }
            }
        }

        /// <summary>
        /// Gets or sets nonce expire time in seconds.
        /// </summary>
        public int ExpireTime
        {
            get { return _expireTime; }
            set
            {
                if (value < 5)
                    throw new ArgumentException("Property ExpireTime value must be >= 5 !");
                _expireTime = value;
            }
        }
    }
}
