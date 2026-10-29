using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KeePassNatMsg.Passkeys
{
    public sealed class RegisteredCredential
    {
        public string CredentialId;
        public string PrivateKeyPem;
        public JObject Response;
    }

    /// <summary>
    /// Builds WebAuthn credentials the same way as KeePassXC's BrowserPasskeys,
    /// so passkeys are interchangeable between KeePass and KeePassXC.
    /// </summary>
    public static class PasskeyCrypto
    {
        // KeePassXC AAGUID: fdb141b2-5d84-443e-8a35-4698c205a502
        private static readonly byte[] Aaguid = {
            0xfd, 0xb1, 0x41, 0xb2, 0x5d, 0x84, 0x44, 0x3e,
            0x8a, 0x35, 0x46, 0x98, 0xc2, 0x05, 0xa5, 0x02
        };

        private const int IdBytes = 32;
        private const int RsaBits = 2048;

        // https://w3c.github.io/webauthn/#table-authData
        private const byte FlagUP = 1 << 0;
        private const byte FlagUV = 1 << 2;
        private const byte FlagBE = 1 << 3;
        private const byte FlagBS = 1 << 4;
        private const byte FlagAT = 1 << 6;
        private const byte FlagED = 1 << 7;

        private static readonly SecureRandom Random = new SecureRandom();

        public static RegisteredCredential BuildRegisterCredential(CredentialCreationOptions options)
        {
            return BuildRegisterCredential(options, null, null);
        }

        // credentialId and ecPrivateKey are only set by tests to get a predictable result
        public static RegisteredCredential BuildRegisterCredential(CredentialCreationOptions options, byte[] credentialId, BigInteger ecPrivateKey)
        {
            if (credentialId == null)
            {
                credentialId = new byte[IdBytes];
                Random.NextBytes(credentialId);
            }

            var keyPair = GenerateKeyPair(options.Algorithm, ecPrivateKey);
            var coseKey = EncodeCosePublicKey(options.Algorithm, keyPair.Public);

            // Attested credential data: AAGUID, credential ID length and ID, public key
            var authData = new MemoryStream();
            var baseData = BuildAuthenticatorData(options.RpId, null, true, true, true);
            authData.Write(baseData, 0, baseData.Length);
            authData.Write(Aaguid, 0, Aaguid.Length);
            authData.WriteByte((byte)(credentialId.Length >> 8));
            authData.WriteByte((byte)credentialId.Length);
            authData.Write(credentialId, 0, credentialId.Length);
            authData.Write(coseKey, 0, coseKey.Length);
            if (options.Extensions != null)
            {
                authData.Write(options.Extensions, 0, options.Extensions.Length);
                authData.GetBuffer()[32] |= FlagED;
            }

            // https://w3c.github.io/webauthn/#sctn-none-attestation
            var attestation = new CborWriter();
            attestation.WriteMapHeader(3);
            attestation.WriteText("fmt");
            attestation.WriteText("none");
            attestation.WriteText("attStmt");
            attestation.WriteMapHeader(0);
            attestation.WriteText("authData");
            attestation.WriteBytes(authData.ToArray());

            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded();
            var id = Base64Url.Encode(credentialId);

            var response = new JObject
            {
                { "attestationObject", Base64Url.Encode(attestation.ToArray()) },
                { "clientDataJSON", Base64Url.Encode(Encoding.UTF8.GetBytes(options.ClientDataJson)) },
                { "clientExtensionResults", options.ClientExtensionResults },
                // Additions for extension side functions
                { "authenticatorData", Base64Url.Encode(BuildAuthenticatorData(options.RpId, options.Extensions, false, true, true)) },
                { "publicKey", Base64Url.Encode(spki) },
                { "publicKeyAlgorithm", options.Algorithm },
            };

            return new RegisteredCredential
            {
                CredentialId = id,
                PrivateKeyPem = EncodePem(EncodePrivateKey(keyPair.Private)),
                Response = new JObject
                {
                    { "authenticatorAttachment", options.AuthenticatorAttachment },
                    { "id", id },
                    { "response", response },
                    { "type", PasskeyOptions.PublicKeyType },
                },
            };
        }

        public static JObject BuildGetCredential(AssertionOptions options, string credentialId, string userHandle, string privateKeyPem, bool beFlag, bool bsFlag)
        {
            var authenticatorData = BuildAuthenticatorData(options.RpId, options.Extensions, false, beFlag, bsFlag);
            var clientData = Encoding.UTF8.GetBytes(options.ClientDataJson);

            var signature = Sign(authenticatorData, clientData, privateKeyPem);
            if (signature == null)
                return null;

            var response = new JObject
            {
                { "authenticatorData", Base64Url.Encode(authenticatorData) },
                { "clientDataJSON", Base64Url.Encode(clientData) },
                { "clientExtensionResults", options.ClientExtensionResults },
                { "signature", Base64Url.Encode(signature) },
                { "userHandle", userHandle },
            };

            return new JObject
            {
                { "authenticatorAttachment", PasskeyOptions.AttachmentPlatform },
                { "id", credentialId },
                { "response", response },
                { "type", PasskeyOptions.PublicKeyType },
            };
        }

        // rpIdHash, flags and a signature counter that is always 0
        private static byte[] BuildAuthenticatorData(string rpId, byte[] extensions, bool attested, bool beFlag, bool bsFlag)
        {
            var result = new MemoryStream();
            var rpIdHash = Sha256(Encoding.UTF8.GetBytes(rpId));
            result.Write(rpIdHash, 0, rpIdHash.Length);

            var flags = (byte)(FlagUP | FlagUV);
            if (beFlag) flags |= FlagBE;
            if (bsFlag) flags |= FlagBS;
            if (attested) flags |= FlagAT;
            if (extensions != null && !attested) flags |= FlagED;
            result.WriteByte(flags);

            result.Write(new byte[4], 0, 4);

            if (extensions != null && !attested)
                result.Write(extensions, 0, extensions.Length);

            return result.ToArray();
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair(int alg, BigInteger ecPrivateKey)
        {
            if (alg == PasskeyOptions.RS256)
            {
                var generator = new RsaKeyPairGenerator();
                generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), Random, RsaBits, 100));
                return generator.GenerateKeyPair();
            }

            if (alg == PasskeyOptions.EdDSA)
            {
                var generator = new Ed25519KeyPairGenerator();
                generator.Init(new Ed25519KeyGenerationParameters(Random));
                return generator.GenerateKeyPair();
            }

            var curve = SecObjectIdentifiers.SecP256r1;
            if (ecPrivateKey != null)
            {
                var domain = ECNamedCurveTable.GetByOid(curve);
                var q = domain.G.Multiply(ecPrivateKey).Normalize();
                return new AsymmetricCipherKeyPair(
                    new ECPublicKeyParameters("EC", q, curve),
                    new ECPrivateKeyParameters("EC", ecPrivateKey, curve));
            }

            var ecGenerator = new ECKeyPairGenerator("EC");
            ecGenerator.Init(new ECKeyGenerationParameters(curve, Random));
            return ecGenerator.GenerateKeyPair();
        }

        // https://w3c.github.io/webauthn/#sctn-encoded-credPubKey-examples
        private static byte[] EncodeCosePublicKey(int alg, AsymmetricKeyParameter publicKey)
        {
            var cbor = new CborWriter();
            if (alg == PasskeyOptions.RS256)
            {
                var rsa = (RsaKeyParameters)publicKey;
                cbor.WriteMapHeader(4);
                cbor.WriteInt(1); cbor.WriteInt(3); // kty: RSA
                cbor.WriteInt(3); cbor.WriteInt(alg);
                cbor.WriteInt(-1); cbor.WriteBytes(rsa.Modulus.ToByteArrayUnsigned());
                cbor.WriteInt(-2); cbor.WriteBytes(rsa.Exponent.ToByteArrayUnsigned());
            }
            else if (alg == PasskeyOptions.EdDSA)
            {
                cbor.WriteMapHeader(4);
                cbor.WriteInt(1); cbor.WriteInt(1); // kty: OKP
                cbor.WriteInt(3); cbor.WriteInt(alg);
                cbor.WriteInt(-1); cbor.WriteInt(6); // crv: Ed25519
                cbor.WriteInt(-2); cbor.WriteBytes(((Ed25519PublicKeyParameters)publicKey).GetEncoded());
            }
            else
            {
                var q = ((ECPublicKeyParameters)publicKey).Q;
                cbor.WriteMapHeader(5);
                cbor.WriteInt(1); cbor.WriteInt(2); // kty: EC2
                cbor.WriteInt(3); cbor.WriteInt(alg);
                cbor.WriteInt(-1); cbor.WriteInt(1); // crv: P-256
                cbor.WriteInt(-2); cbor.WriteBytes(q.AffineXCoord.GetEncoded());
                cbor.WriteInt(-3); cbor.WriteBytes(q.AffineYCoord.GetEncoded());
            }
            return cbor.ToArray();
        }

        private static byte[] Sign(byte[] authenticatorData, byte[] clientData, string privateKeyPem)
        {
            AsymmetricKeyParameter key;
            try
            {
                key = PrivateKeyFactory.CreateKey(DecodePem(privateKeyPem));
            }
            catch (Exception)
            {
                return null;
            }

            ISigner signer;
            if (key is ECPrivateKeyParameters)
                signer = new DsaDigestSigner(new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest())), new Sha256Digest());
            else if (key is RsaKeyParameters)
                signer = new RsaDigestSigner(new Sha256Digest());
            else if (key is Ed25519PrivateKeyParameters)
                signer = new Ed25519Signer();
            else
                return null;

            var clientDataHash = Sha256(clientData);
            signer.Init(true, key);
            signer.BlockUpdate(authenticatorData, 0, authenticatorData.Length);
            signer.BlockUpdate(clientDataHash, 0, clientDataHash.Length);
            return signer.GenerateSignature();
        }

        // Botan (KeePassXC) only reads version 1 PKCS #8 keys, BouncyCastle writes Ed25519 keys as version 2
        private static byte[] EncodePrivateKey(AsymmetricKeyParameter privateKey)
        {
            var info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            return new PrivateKeyInfo(info.PrivateKeyAlgorithm, info.ParsePrivateKey()).GetDerEncoded();
        }

        private static string EncodePem(byte[] der)
        {
            var sb = new StringBuilder("-----BEGIN PRIVATE KEY-----\n");
            var base64 = Convert.ToBase64String(der);
            for (var i = 0; i < base64.Length; i += 64)
            {
                sb.Append(base64, i, Math.Min(64, base64.Length - i)).Append('\n');
            }
            return sb.Append("-----END PRIVATE KEY-----\n").ToString();
        }

        // KeePassXC may store the PEM without line breaks
        private static byte[] DecodePem(string pem)
        {
            var body = pem.Replace("-----BEGIN PRIVATE KEY-----", string.Empty).Replace("-----END PRIVATE KEY-----", string.Empty);
            return Convert.FromBase64String(body.Replace("\r", string.Empty).Replace("\n", string.Empty).Replace(" ", string.Empty));
        }

        private static byte[] Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }
    }

    /// <summary>
    /// Minimal CBOR encoder for the few types WebAuthn needs (RFC 8949)
    /// </summary>
    public sealed class CborWriter
    {
        private readonly MemoryStream _stream = new MemoryStream();

        public void WriteInt(long value)
        {
            if (value >= 0)
                WriteHead(0, (ulong)value);
            else
                WriteHead(1, (ulong)(-1 - value));
        }

        public void WriteBytes(byte[] value)
        {
            WriteHead(2, (ulong)value.Length);
            _stream.Write(value, 0, value.Length);
        }

        public void WriteText(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            WriteHead(3, (ulong)bytes.Length);
            _stream.Write(bytes, 0, bytes.Length);
        }

        public void WriteArrayHeader(int count)
        {
            WriteHead(4, (ulong)count);
        }

        public void WriteMapHeader(int count)
        {
            WriteHead(5, (ulong)count);
        }

        public void WriteBool(bool value)
        {
            _stream.WriteByte(value ? (byte)0xf5 : (byte)0xf4);
        }

        public byte[] ToArray()
        {
            return _stream.ToArray();
        }

        private void WriteHead(int majorType, ulong value)
        {
            var type = (byte)(majorType << 5);
            if (value < 24)
            {
                _stream.WriteByte((byte)(type | (byte)value));
                return;
            }

            int length;
            if (value <= byte.MaxValue) { _stream.WriteByte((byte)(type | 24)); length = 1; }
            else if (value <= ushort.MaxValue) { _stream.WriteByte((byte)(type | 25)); length = 2; }
            else if (value <= uint.MaxValue) { _stream.WriteByte((byte)(type | 26)); length = 4; }
            else { _stream.WriteByte((byte)(type | 27)); length = 8; }

            for (var i = length - 1; i >= 0; i--)
            {
                _stream.WriteByte((byte)(value >> (8 * i)));
            }
        }
    }
}
