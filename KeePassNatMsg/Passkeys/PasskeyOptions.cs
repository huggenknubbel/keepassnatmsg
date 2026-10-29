using KeePassNatMsg.Protocol;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.Linq;

namespace KeePassNatMsg.Passkeys
{
    public sealed class CredentialCreationOptions
    {
        public string Origin;
        public string RpId;
        public string RpName;
        public string UserName;
        public string UserId;
        public string ClientDataJson;
        public string AuthenticatorAttachment;
        public int Algorithm;
        public JArray ExcludeCredentials;
        public byte[] Extensions;
        public JObject ClientExtensionResults;
    }

    public sealed class AssertionOptions
    {
        public string RpId;
        public string ClientDataJson;
        public JArray AllowCredentials;
        public byte[] Extensions;
        public JObject ClientExtensionResults;
    }

    /// <summary>
    /// Validates the PublicKeyCredential options sent by keepassxc-browser,
    /// following KeePassXC's BrowserPasskeysClient and PasskeyUtils.
    /// </summary>
    public static class PasskeyOptions
    {
        public const int ES256 = -7;
        public const int EdDSA = -8;
        public const int RS256 = -257;

        public const string PublicKeyType = "public-key";
        public const string AttachmentPlatform = "platform";
        public const string AttachmentCrossPlatform = "cross-platform";

        public static ErrorType GetCredentialCreationOptions(JObject publicKey, string origin, out CredentialCreationOptions result)
        {
            result = null;

            var challenge = (string)publicKey["challenge"];
            if (string.IsNullOrEmpty(challenge) || challenge.Length < 16)
                return ErrorType.PasskeysInvalidChallenge;

            var user = publicKey["user"] as JObject;
            var userId = user == null ? null : (string)user["id"];
            var userIdBytes = string.IsNullOrEmpty(userId) ? null : Base64Url.Decode(userId);
            if (userIdBytes == null || userIdBytes.Length < 1 || userIdBytes.Length > 64)
                return ErrorType.PasskeysInvalidUserId;

            string effectiveDomain;
            var error = GetEffectiveDomain(origin, out effectiveDomain);
            if (error != 0)
                return error;

            var rp = publicKey["rp"] as JObject;
            string rpId;
            error = ValidateRpId(rp == null ? null : rp["id"], effectiveDomain, out rpId);
            if (error != 0)
                return error;

            int alg;
            if (!GetAlgorithm(publicKey["pubKeyCredParams"] as JArray, out alg))
                return ErrorType.PasskeysNoSupportedAlgorithms;

            var authenticatorSelection = publicKey["authenticatorSelection"] as JObject;
            var attachment = authenticatorSelection == null ? null : (string)authenticatorSelection["authenticatorAttachment"];
            if (string.IsNullOrEmpty(attachment))
                attachment = AttachmentPlatform;
            else if (attachment != AttachmentPlatform && attachment != AttachmentCrossPlatform)
                return ErrorType.PasskeysWaitForLifetimer;

            result = new CredentialCreationOptions
            {
                Origin = origin,
                RpId = rpId,
                RpName = rp == null ? null : (string)rp["name"],
                UserName = (string)user["name"],
                UserId = userId,
                ClientDataJson = BuildClientDataJson(challenge, origin, false),
                AuthenticatorAttachment = attachment,
                Algorithm = alg,
                ExcludeCredentials = publicKey["excludeCredentials"] as JArray ?? new JArray(),
            };
            BuildExtensionData(publicKey["extensions"] as JObject, out result.Extensions, out result.ClientExtensionResults);
            return 0;
        }

        public static ErrorType GetAssertionOptions(JObject publicKey, string origin, out AssertionOptions result)
        {
            result = null;

            string effectiveDomain;
            var error = GetEffectiveDomain(origin, out effectiveDomain);
            if (error != 0)
                return error;

            string rpId;
            error = ValidateRpId(publicKey["rpId"], effectiveDomain, out rpId);
            if (error != 0)
                return error;

            result = new AssertionOptions
            {
                RpId = rpId,
                ClientDataJson = BuildClientDataJson((string)publicKey["challenge"], origin, true),
                AllowCredentials = publicKey["allowCredentials"] as JArray ?? new JArray(),
            };
            BuildExtensionData(publicKey["extensions"] as JObject, out result.Extensions, out result.ClientExtensionResults);
            return 0;
        }

        public static bool IsOriginAllowed(string origin)
        {
            return !string.IsNullOrEmpty(origin) && origin.StartsWith("https://", StringComparison.Ordinal);
        }

        private static ErrorType GetEffectiveDomain(string origin, out string result)
        {
            result = null;
            Uri uri;
            if (string.IsNullOrEmpty(origin) || !Uri.TryCreate(origin, UriKind.Absolute, out uri))
                return ErrorType.PasskeysOriginNotAllowed;

            string host;
            try
            {
                host = new IdnMapping().GetAscii(uri.Host);
            }
            catch (ArgumentException)
            {
                return ErrorType.PasskeysDomainIsNotValid;
            }

            if (!IsDomain(host))
                return ErrorType.PasskeysDomainIsNotValid;

            result = host;
            return 0;
        }

        // The RP ID defaults to the origin's effective domain unless options.rp.id is set
        private static ErrorType ValidateRpId(JToken rpIdValue, string effectiveDomain, out string result)
        {
            result = null;
            if (rpIdValue == null || rpIdValue.Type == JTokenType.Null || rpIdValue.Type == JTokenType.Undefined)
            {
                result = effectiveDomain;
                return 0;
            }

            var rpId = ((string)rpIdValue ?? string.Empty).ToLowerInvariant();
            if (!IsRegistrableDomainSuffix(rpId, effectiveDomain))
                return ErrorType.PasskeysDomainRpIdMismatch;

            result = rpId;
            return 0;
        }

        // Without a public suffix list, only reject bare top-level domains as RP ID suffixes
        private static bool IsRegistrableDomainSuffix(string hostSuffix, string originalHost)
        {
            if (string.IsNullOrEmpty(hostSuffix) || !IsDomain(originalHost))
                return false;

            if (hostSuffix == originalHost)
                return true;

            return IsDomain(hostSuffix) && hostSuffix.Contains(".") && originalHost.EndsWith("." + hostSuffix, StringComparison.Ordinal);
        }

        private static bool IsDomain(string host)
        {
            return !string.IsNullOrEmpty(host) && !host.EndsWith(".") && host.All(c => c < 128)
                && Uri.CheckHostName(host) == UriHostNameType.Dns;
        }

        // Returns the first supported algorithm. ES256 is the default when no parameters are given.
        private static bool GetAlgorithm(JArray pubKeyCredParams, out int alg)
        {
            alg = ES256;
            if (pubKeyCredParams == null || pubKeyCredParams.Count == 0)
                return true;

            foreach (var param in pubKeyCredParams.OfType<JObject>())
            {
                var value = param["alg"];
                if ((string)param["type"] != PublicKeyType || value == null || value.Type != JTokenType.Integer)
                    continue;

                var current = (int)value;
                if (current == ES256 || current == EdDSA || current == RS256)
                {
                    alg = current;
                    return true;
                }
            }
            return false;
        }

        // Serialization order: https://w3c.github.io/webauthn/#clientdatajson-serialization
        private static string BuildClientDataJson(string challenge, string origin, bool get)
        {
            return string.Format("{{\"type\":\"{0}\",\"challenge\":\"{1}\",\"origin\":\"{2}\",\"crossOrigin\":false}}",
                get ? "webauthn.get" : "webauthn.create", challenge, origin);
        }

        // Only credProps and uvm are supported
        private static void BuildExtensionData(JObject extensions, out byte[] data, out JObject results)
        {
            data = null;
            results = new JObject();

            var credProps = extensions != null && extensions["credProps"] != null && extensions["credProps"].Type == JTokenType.Boolean && (bool)extensions["credProps"];
            var uvm = extensions != null && extensions["uvm"] != null && extensions["uvm"].Type == JTokenType.Boolean && (bool)extensions["uvm"];
            if (!credProps && !uvm)
                return;

            var cbor = new CborWriter();
            cbor.WriteMapHeader((credProps ? 1 : 0) + (uvm ? 1 : 0));

            // https://w3c.github.io/webauthn/#sctn-authenticator-credential-properties-extension
            if (credProps)
            {
                cbor.WriteText("credProps");
                cbor.WriteMapHeader(1);
                cbor.WriteText("rk");
                cbor.WriteBool(true);
                results["credProps"] = new JObject { { "rk", true } };
            }

            // https://w3c.github.io/webauthn/#sctn-uvm-extension
            // presence_internal, software key protection, software matcher protection
            if (uvm)
            {
                cbor.WriteText("uvm");
                cbor.WriteArrayHeader(1);
                cbor.WriteArrayHeader(3);
                cbor.WriteInt(1);
                cbor.WriteInt(1);
                cbor.WriteInt(1);
                results["uvm"] = new JArray { new JArray { 1, 1, 1 } };
            }

            data = cbor.ToArray();
        }
    }

    public static class Base64Url
    {
        public static string Encode(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static byte[] Decode(string s)
        {
            try
            {
                s = s.Replace('-', '+').Replace('_', '/');
                return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
            }
            catch (FormatException)
            {
                return null;
            }
        }
    }
}
