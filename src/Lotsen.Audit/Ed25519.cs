using System.Security.Cryptography;
using NSec.Cryptography;

namespace Lotsen.Audit;

public sealed record AuditKeyPair(string PrivateKeyBase64, string PublicKeyBase64, string KeyId);

public static class AuditKeyIds
{
    /// <summary>A short, stable id stored on every entry so keys can be rotated later.</summary>
    public static string FromPublicKey(ReadOnlySpan<byte> publicKey) =>
        "ed25519:" + Convert.ToHexStringLower(SHA256.HashData(publicKey))[..16];
}

public static class Ed25519Keys
{
    private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;

    public static AuditKeyPair Generate()
    {
        using var key = Key.Create(
            Algorithm,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

        byte[] privateKey = key.Export(KeyBlobFormat.RawPrivateKey);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        try
        {
            return new AuditKeyPair(
                Convert.ToBase64String(privateKey),
                Convert.ToBase64String(publicKey),
                AuditKeyIds.FromPublicKey(publicKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }
    }
}

public sealed class Ed25519AuditSigner : IAuditSigner, IDisposable
{
    private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;
    private readonly Key _key;

    private Ed25519AuditSigner(Key key)
    {
        _key = key;
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        PublicKeyBase64 = Convert.ToBase64String(publicKey);
        KeyId = AuditKeyIds.FromPublicKey(publicKey);
    }

    public string KeyId { get; }

    public string PublicKeyBase64 { get; }

    public static Ed25519AuditSigner FromBase64PrivateKey(string privateKeyBase64)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyBase64);
        byte[] raw = Convert.FromBase64String(privateKeyBase64.Trim());
        try
        {
            return new Ed25519AuditSigner(Key.Import(Algorithm, raw, KeyBlobFormat.RawPrivateKey));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    public byte[] Sign(ReadOnlySpan<byte> data) => Algorithm.Sign(_key, data);

    public void Dispose() => _key.Dispose();
}

public sealed class Ed25519SignatureVerifier : IAuditSignatureVerifier
{
    private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;
    private readonly Dictionary<string, PublicKey> _keys = new(StringComparer.Ordinal);

    public Ed25519SignatureVerifier(IEnumerable<string> publicKeysBase64)
    {
        ArgumentNullException.ThrowIfNull(publicKeysBase64);
        foreach (string encoded in publicKeysBase64.Where(k => !string.IsNullOrWhiteSpace(k)))
        {
            byte[] raw = Convert.FromBase64String(encoded.Trim());
            _keys[AuditKeyIds.FromPublicKey(raw)] = PublicKey.Import(Algorithm, raw, KeyBlobFormat.RawPublicKey);
        }

        if (_keys.Count == 0)
        {
            throw new ArgumentException("At least one trusted public key is required.", nameof(publicKeysBase64));
        }
    }

    public IReadOnlyCollection<string> TrustedKeyIds => _keys.Keys;

    public bool Verify(string keyId, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
        _keys.TryGetValue(keyId, out var key) && Algorithm.Verify(key, data, signature);
}
