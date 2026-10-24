namespace Glacier.Codec.Cryptography.PostQuantum;

using System;
using System.Security.Cryptography;
using Glacier.Codec.Memory;

/// <summary>
/// Common engine base class and factory for FIPS 203 ML-KEM post-quantum key encapsulation mechanisms.
/// Conforms to NIST FIPS 203 standard for Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).
/// </summary>
public abstract class MlKemEngine : IKeyEncapsulationMechanism, IDisposable
{
    private static readonly Lazy<MlKem768> s_mlKem768 = new(() => new MlKem768());
    private static readonly Lazy<MlKem1024> s_mlKem1024 = new(() => new MlKem1024());

    /// <summary>Singleton instance of FIPS 203 ML-KEM-768 (Rank k=3, NIST Level 3).</summary>
    public static MlKem768 MlKem768 => s_mlKem768.Value;

    /// <summary>Singleton instance of FIPS 203 ML-KEM-1024 (Rank k=4, NIST Level 5).</summary>
    public static MlKem1024 MlKem1024 => s_mlKem1024.Value;

    public int RankK { get; }
    public int Du { get; }
    public int Dv { get; }

    public abstract int PublicKeySizeInBytes { get; }
    public abstract int SecretKeySizeInBytes { get; }
    public abstract int CiphertextSizeInBytes { get; }
    public int SharedSecretSizeInBytes => 32;

    protected MlKemEngine(int rankK, int du, int dv)
    {
        RankK = rankK;
        Du = du;
        Dv = dv;
    }

    public abstract void GenerateKeyPair(Span<byte> publicKey, Span<byte> secretKey);
    public abstract void Encapsulate(ReadOnlySpan<byte> publicKey, Span<byte> ciphertext, Span<byte> sharedSecret);
    public abstract bool Decapsulate(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret);

    /// <summary>Generates a managed key pair container with secure memory for the secret key.</summary>
    public MlKemKeyPair CreateKeyPair()
    {
        var sk = new SecureMemory(SecretKeySizeInBytes);
        byte[] pk = new byte[PublicKeySizeInBytes];
        GenerateKeyPair(pk, sk.Span);
        return new MlKemKeyPair(this, pk, sk);
    }

    /// <summary>
    /// FIPS 203 Algorithm 16 (ML-KEM.KeyGen_internal): Deterministic key pair generation from seeds (d, z).
    /// </summary>
    internal unsafe void KeyGenInternal(
        ReadOnlySpan<byte> d,
        ReadOnlySpan<byte> z,
        Span<byte> publicKey,
        Span<byte> secretKey)
    {
        int k = RankK;
        int ekLen = PublicKeySizeInBytes;
        int skLen = SecretKeySizeInBytes;

        // 1. (rho, sigma) = G(d || k) (64 bytes)
        Span<byte> dkSeed = stackalloc byte[33];
        d.Slice(0, 32).CopyTo(dkSeed.Slice(0, 32));
        dkSeed[32] = (byte)k;

        Span<byte> gDigest = stackalloc byte[64];
        KeccakSponge.Sha3_512(dkSeed, gDigest);
        ReadOnlySpan<byte> rho = gDigest.Slice(0, 32);
        ReadOnlySpan<byte> sigma = gDigest.Slice(32, 32);

        // 2. Generate matrix A_hat[i, j] = SampleNTT(rho || j || i)
        // Memory for k * k polynomials (256 shorts each)
        short* aHat = stackalloc short[k * k * 256];
        for (byte i = 0; i < k; i++)
        {
            for (byte j = 0; j < k; j++)
            {
                Span<short> aHatElem = new(aHat + (i * k + j) * 256, 256);
                KeccakSponge.SampleNTT(rho, j, i, aHatElem);
            }
        }

        // 3. Sample secret vector s and error vector e
        short* sHat = stackalloc short[k * 256];
        short* eHat = stackalloc short[k * 256];
        Span<byte> prfOut = stackalloc byte[128];

        byte n = 0;
        for (int i = 0; i < k; i++)
        {
            KeccakSponge.Prf2(sigma, n++, prfOut);
            Span<short> sElem = new(sHat + i * 256, 256);
            KeccakSponge.SamplePolyCBD_2(prfOut, sElem);
            NttTransform.ForwardNtt(sElem);
        }

        for (int i = 0; i < k; i++)
        {
            KeccakSponge.Prf2(sigma, n++, prfOut);
            Span<short> eElem = new(eHat + i * 256, 256);
            KeccakSponge.SamplePolyCBD_2(prfOut, eElem);
            NttTransform.ForwardNtt(eElem);
        }

        // 4. Compute t_hat = A_hat o s_hat + e_hat
        short* tHat = stackalloc short[k * 256];
        short* prod = stackalloc short[256];
        Span<short> prodSpan = new(prod, 256);

        for (int i = 0; i < k; i++)
        {
            Span<short> tElem = new(tHat + i * 256, 256);
            Span<short> eElem = new(eHat + i * 256, 256);
            eElem.CopyTo(tElem);

            for (int j = 0; j < k; j++)
            {
                ReadOnlySpan<short> aElem = new(aHat + (i * k + j) * 256, 256);
                ReadOnlySpan<short> sElem = new(sHat + j * 256, 256);
                NttTransform.MultiplyNTTs(aElem, sElem, prodSpan);
                NttTransform.PolyAdd(tElem, prodSpan, tElem);
            }
        }

        // 5. Encode public key: ek = ByteEncode_12(t_hat) || rho
        for (int i = 0; i < k; i++)
        {
            ReadOnlySpan<short> tElem = new(tHat + i * 256, 256);
            Polyvec.ByteEncode12(tElem, publicKey.Slice(384 * i, 384));
        }
        rho.CopyTo(publicKey.Slice(384 * k, 32));

        // 6. Encode secret key: dk = ByteEncode_12(s_hat) || ek || H(ek) || z
        for (int i = 0; i < k; i++)
        {
            ReadOnlySpan<short> sElem = new(sHat + i * 256, 256);
            Polyvec.ByteEncode12(sElem, secretKey.Slice(384 * i, 384));
        }
        publicKey.Slice(0, ekLen).CopyTo(secretKey.Slice(384 * k, ekLen));

        Span<byte> h = stackalloc byte[32];
        KeccakSponge.Sha3_256(publicKey.Slice(0, ekLen), h);
        h.CopyTo(secretKey.Slice(384 * k + ekLen, 32));

        z.Slice(0, 32).CopyTo(secretKey.Slice(384 * k + ekLen + 32, 32));

        // Zeroize scratch buffers
        CryptographicOperations.ZeroMemory(new Span<byte>(aHat, k * k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(sHat, k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(eHat, k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(tHat, k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(dkSeed);
        CryptographicOperations.ZeroMemory(gDigest);
        CryptographicOperations.ZeroMemory(prfOut);
        CryptographicOperations.ZeroMemory(h);
    }

    /// <summary>
    /// FIPS 203 Algorithm 17 (ML-KEM.Encaps_internal): Deterministic encapsulation from message m.
    /// </summary>
    internal unsafe void EncapsInternal(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> m,
        Span<byte> ciphertext,
        Span<byte> sharedSecret)
    {
        int k = RankK;
        int ekLen = PublicKeySizeInBytes;

        // 1. h = H(ek)
        Span<byte> h = stackalloc byte[32];
        KeccakSponge.Sha3_256(publicKey.Slice(0, ekLen), h);

        // 2. (K, r) = G(m || h) (64 bytes)
        Span<byte> mh = stackalloc byte[64];
        m.Slice(0, 32).CopyTo(mh.Slice(0, 32));
        h.CopyTo(mh.Slice(32, 32));

        Span<byte> kr = stackalloc byte[64];
        KeccakSponge.Sha3_512(mh, kr);
        kr.Slice(0, 32).CopyTo(sharedSecret.Slice(0, 32));
        ReadOnlySpan<byte> r = kr.Slice(32, 32);

        // 3. K-PKE.Encrypt(ek, m, r)
        EncryptPke(publicKey, m, r, ciphertext);

        CryptographicOperations.ZeroMemory(h);
        CryptographicOperations.ZeroMemory(mh);
        CryptographicOperations.ZeroMemory(kr);
    }

    /// <summary>
    /// FIPS 203 Algorithm 18 (ML-KEM.Decaps_internal): Decapsulates ciphertext with constant-time implicit rejection.
    /// </summary>
    internal unsafe bool DecapsInternal(
        ReadOnlySpan<byte> secretKey,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> sharedSecret)
    {
        int k = RankK;
        int ekLen = PublicKeySizeInBytes;
        int ctLen = CiphertextSizeInBytes;

        ReadOnlySpan<byte> dkPke = secretKey.Slice(0, 384 * k);
        ReadOnlySpan<byte> ekPke = secretKey.Slice(384 * k, ekLen);
        ReadOnlySpan<byte> h = secretKey.Slice(384 * k + ekLen, 32);
        ReadOnlySpan<byte> z = secretKey.Slice(384 * k + ekLen + 32, 32);

        // 1. m' = K-PKE.Decrypt(dk_PKE, c)
        Span<byte> mPrime = stackalloc byte[32];
        DecryptPke(dkPke, ciphertext, mPrime);

        // 2. (K', r') = G(m' || h)
        Span<byte> mh = stackalloc byte[64];
        mPrime.CopyTo(mh.Slice(0, 32));
        h.CopyTo(mh.Slice(32, 32));

        Span<byte> krPrime = stackalloc byte[64];
        KeccakSponge.Sha3_512(mh, krPrime);
        ReadOnlySpan<byte> kPrime = krPrime.Slice(0, 32);
        ReadOnlySpan<byte> rPrime = krPrime.Slice(32, 32);

        // 3. K_reject = J(z || c) = SHAKE-256(z || c, 32)
        Span<byte> kReject = stackalloc byte[32];
        var shakeReject = new KeccakSponge(rateInBytes: 136);
        shakeReject.Absorb(z);
        shakeReject.Absorb(ciphertext.Slice(0, ctLen));
        shakeReject.Pad(0x1F);
        shakeReject.Squeeze(kReject);

        // 4. c' = K-PKE.Encrypt(ek_PKE, m', r')
        Span<byte> cPrime = stackalloc byte[ctLen];
        EncryptPke(ekPke, mPrime, rPrime, cPrime);

        // 5. Branchless implicit rejection check
        bool match = CryptographicOperations.FixedTimeEquals(ciphertext.Slice(0, ctLen), cPrime);
        byte mask = (byte)(match ? 0xFF : 0x00);

        for (int i = 0; i < 32; i++)
        {
            sharedSecret[i] = (byte)((kPrime[i] & mask) | (kReject[i] & ~mask));
        }

        // Cleanup
        CryptographicOperations.ZeroMemory(mPrime);
        CryptographicOperations.ZeroMemory(mh);
        CryptographicOperations.ZeroMemory(krPrime);
        CryptographicOperations.ZeroMemory(kReject);
        CryptographicOperations.ZeroMemory(cPrime);

        return match;
    }

    /// <summary>
    /// FIPS 203 Algorithm 14 (K-PKE.Encrypt): Encrypts message m under public key ek with randomness r.
    /// </summary>
    private unsafe void EncryptPke(
        ReadOnlySpan<byte> ek,
        ReadOnlySpan<byte> m,
        ReadOnlySpan<byte> r,
        Span<byte> ciphertext)
    {
        int k = RankK;

        // 1. Decode t_hat and extract rho
        short* tHat = stackalloc short[k * 256];
        for (int i = 0; i < k; i++)
        {
            Span<short> tElem = new(tHat + i * 256, 256);
            Polyvec.ByteDecode12(ek.Slice(384 * i, 384), tElem);
        }
        ReadOnlySpan<byte> rho = ek.Slice(384 * k, 32);

        // 2. Sample matrix A_hat[i, j] = SampleNTT(rho || j || i)
        short* aHat = stackalloc short[k * k * 256];
        for (byte i = 0; i < k; i++)
        {
            for (byte j = 0; j < k; j++)
            {
                Span<short> aElem = new(aHat + (i * k + j) * 256, 256);
                KeccakSponge.SampleNTT(rho, j, i, aElem);
            }
        }

        // 3. Sample vector y, vector e1, and scalar e2
        short* yHat = stackalloc short[k * 256];
        short* e1 = stackalloc short[k * 256];
        short* e2 = stackalloc short[256];
        Span<short> e2Span = new(e2, 256);
        Span<byte> prfOut = stackalloc byte[128];

        byte n = 0;
        for (int i = 0; i < k; i++)
        {
            KeccakSponge.Prf2(r, n++, prfOut);
            Span<short> yElem = new(yHat + i * 256, 256);
            KeccakSponge.SamplePolyCBD_2(prfOut, yElem);
            NttTransform.ForwardNtt(yElem);
        }

        for (int i = 0; i < k; i++)
        {
            KeccakSponge.Prf2(r, n++, prfOut);
            Span<short> e1Elem = new(e1 + i * 256, 256);
            KeccakSponge.SamplePolyCBD_2(prfOut, e1Elem);
        }

        KeccakSponge.Prf2(r, n++, prfOut);
        KeccakSponge.SamplePolyCBD_2(prfOut, e2Span);

        // 4. Compute u = INTT(A_hat^T o y_hat) + e1
        // Note: A_hat^T[i, j] = A_hat[j, i]
        short* u = stackalloc short[k * 256];
        short* prod = stackalloc short[256];
        Span<short> prodSpan = new(prod, 256);

        for (int i = 0; i < k; i++)
        {
            Span<short> uElem = new(u + i * 256, 256);
            uElem.Clear();

            for (int j = 0; j < k; j++)
            {
                // A_hat^T[i, j] = A_hat[j, i]
                ReadOnlySpan<short> aElem = new(aHat + (j * k + i) * 256, 256);
                ReadOnlySpan<short> yElem = new(yHat + j * 256, 256);
                NttTransform.MultiplyNTTs(aElem, yElem, prodSpan);
                NttTransform.PolyAdd(uElem, prodSpan, uElem);
            }

            NttTransform.InverseNtt(uElem);
            ReadOnlySpan<short> e1Elem = new(e1 + i * 256, 256);
            NttTransform.PolyAdd(uElem, e1Elem, uElem);
        }

        // 5. Compute mu = Decompress_1(ByteDecode_1(m))
        short* mu = stackalloc short[256];
        Span<short> muSpan = new(mu, 256);
        Polyvec.DecodeAndDecompress1(m, muSpan);

        // 6. Compute v = INTT(t_hat^T o y_hat) + e2 + mu
        short* v = stackalloc short[256];
        Span<short> vSpan = new(v, 256);
        vSpan.Clear();

        for (int i = 0; i < k; i++)
        {
            ReadOnlySpan<short> tElem = new(tHat + i * 256, 256);
            ReadOnlySpan<short> yElem = new(yHat + i * 256, 256);
            NttTransform.MultiplyNTTs(tElem, yElem, prodSpan);
            NttTransform.PolyAdd(vSpan, prodSpan, vSpan);
        }

        NttTransform.InverseNtt(vSpan);
        NttTransform.PolyAdd(vSpan, e2Span, vSpan);
        NttTransform.PolyAdd(vSpan, muSpan, vSpan);

        // 7. Compress and encode ciphertext: c1 || c2
        if (k == 3)
        {
            // ML-KEM-768: du = 10, dv = 4
            for (int i = 0; i < 3; i++)
            {
                ReadOnlySpan<short> uElem = new(u + i * 256, 256);
                Polyvec.CompressAndEncode10(uElem, ciphertext.Slice(320 * i, 320));
            }
            Polyvec.CompressAndEncode4(vSpan, ciphertext.Slice(960, 128));
        }
        else
        {
            // ML-KEM-1024: du = 11, dv = 5
            for (int i = 0; i < 4; i++)
            {
                ReadOnlySpan<short> uElem = new(u + i * 256, 256);
                Polyvec.CompressAndEncode11(uElem, ciphertext.Slice(352 * i, 352));
            }
            Polyvec.CompressAndEncode5(vSpan, ciphertext.Slice(1408, 160));
        }

        // Clean stack memory
        CryptographicOperations.ZeroMemory(new Span<byte>(tHat, k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(aHat, k * k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(yHat, k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(e1, k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(e2, 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(u, k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(v, 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(mu, 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(prfOut);
    }

    /// <summary>
    /// FIPS 203 Algorithm 15 (K-PKE.Decrypt): Decrypts ciphertext c to recover message m'.
    /// </summary>
    private unsafe void DecryptPke(
        ReadOnlySpan<byte> dkPke,
        ReadOnlySpan<byte> c,
        Span<byte> mPrime)
    {
        int k = RankK;

        // 1. Decompress and decode u' from c1
        short* uPrime = stackalloc short[k * 256];
        if (k == 3)
        {
            for (int i = 0; i < 3; i++)
            {
                Span<short> uElem = new(uPrime + i * 256, 256);
                Polyvec.DecodeAndDecompress10(c.Slice(320 * i, 320), uElem);
            }
        }
        else
        {
            for (int i = 0; i < 4; i++)
            {
                Span<short> uElem = new(uPrime + i * 256, 256);
                Polyvec.DecodeAndDecompress11(c.Slice(352 * i, 352), uElem);
            }
        }

        // 2. Decompress and decode v' from c2
        short* vPrime = stackalloc short[256];
        Span<short> vPrimeSpan = new(vPrime, 256);
        if (k == 3)
        {
            Polyvec.DecodeAndDecompress4(c.Slice(960, 128), vPrimeSpan);
        }
        else
        {
            Polyvec.DecodeAndDecompress5(c.Slice(1408, 160), vPrimeSpan);
        }

        // 3. Decode s_hat = ByteDecode_12(dk_PKE)
        short* sHat = stackalloc short[k * 256];
        for (int i = 0; i < k; i++)
        {
            Span<short> sElem = new(sHat + i * 256, 256);
            Polyvec.ByteDecode12(dkPke.Slice(384 * i, 384), sElem);
        }

        // 4. Compute NTT(u')
        for (int i = 0; i < k; i++)
        {
            Span<short> uElem = new(uPrime + i * 256, 256);
            NttTransform.ForwardNtt(uElem);
        }

        // 5. Compute w = v' - INTT(s_hat^T o NTT(u'))
        short* term = stackalloc short[256];
        Span<short> termSpan = new(term, 256);
        termSpan.Clear();

        short* prod = stackalloc short[256];
        Span<short> prodSpan = new(prod, 256);

        for (int i = 0; i < k; i++)
        {
            ReadOnlySpan<short> sElem = new(sHat + i * 256, 256);
            ReadOnlySpan<short> uElem = new(uPrime + i * 256, 256);
            NttTransform.MultiplyNTTs(sElem, uElem, prodSpan);
            NttTransform.PolyAdd(termSpan, prodSpan, termSpan);
        }

        NttTransform.InverseNtt(termSpan);

        short* w = stackalloc short[256];
        Span<short> wSpan = new(w, 256);
        NttTransform.PolySub(vPrimeSpan, termSpan, wSpan);

        // 6. m' = ByteEncode_1(Compress_1(w))
        Polyvec.CompressAndEncode1(wSpan, mPrime);

        // Cleanup
        CryptographicOperations.ZeroMemory(new Span<byte>(uPrime, k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(vPrime, 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(sHat, k * 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(term, 256 * sizeof(short)));
        CryptographicOperations.ZeroMemory(new Span<byte>(w, 256 * sizeof(short)));
    }

    public virtual void Dispose() { }
}
