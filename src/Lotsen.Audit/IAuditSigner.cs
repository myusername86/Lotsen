namespace Lotsen.Audit;

/// <summary>Signs entry hashes. Only the API that writes the log holds the private key.</summary>
public interface IAuditSigner
{
    string KeyId { get; }

    byte[] Sign(ReadOnlySpan<byte> data);
}

/// <summary>Checks signatures using public keys only, so anyone can verify without being able to write.</summary>
public interface IAuditSignatureVerifier
{
    bool Verify(string keyId, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
}
