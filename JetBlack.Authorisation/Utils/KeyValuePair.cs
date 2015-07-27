using System;
using System.Collections.Generic;
using System.Linq;

namespace JetBlack.Authorisation.Utils
{
    public static class KeyValuePair
    {
        private static T Identity<T>(T value)
        {
            return value;
        }

        public static KeyValuePair<TKey, TValue> Create<TKey, TValue>(TKey key, TValue value)
        {
            return new KeyValuePair<TKey, TValue>(key, value);
        }

        public static IEnumerable<KeyValuePair<string, string>> ToKeyValuePairs(this string source, char parameterSeparator, char nameValueSeparator)
        {
            return source.ToEnumerable(x => x.Split(parameterSeparator), x => x.ToKeyValuePair(nameValueSeparator));
        }

        public static KeyValuePair<string, string> ToKeyValuePair(this string text, char separator)
        {
            if (text == null)
                return default(KeyValuePair<string, string>);
            var index = text.IndexOf(separator);
            if (index == -1)
                return new KeyValuePair<string, string>(text, string.Empty);

            return new KeyValuePair<string, string>(text.Remove(index), text.Substring(index));
        }

        public static IEnumerable<KeyValuePair<TKey, TValue>> ToEnumerable<TSource, TUnit, TKey, TValue>(this TSource source, Func<TSource, IEnumerable<TUnit>> split, Func<TUnit, KeyValuePair<TKey, TValue>> create)
        {
            return split(source).Select(create);
        }

        public static KeyValuePair<TKeyOut, TValueOut> Mutate<TKeyIn, TValueIn, TKeyOut, TValueOut>(this KeyValuePair<TKeyIn, TValueIn> keyValuePair, Func<TKeyIn, TKeyOut> mutateKey, Func<TValueIn, TValueOut> mutateValue)
        {
            return new KeyValuePair<TKeyOut, TValueOut>(mutateKey(keyValuePair.Key), mutateValue(keyValuePair.Value));
        }
    }
}
