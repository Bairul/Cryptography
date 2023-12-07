import java.util.Arrays;

/**
 * TCSS 387 Cryptography
 * 11/4/2023
 * <p>
 * cSHAKE256 and KMACXOF256 implementation.
 *
 * @author Markku-Juhani Saarinen (<a href="https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c" >Their C code implementation</a>)
 * @author Paulo S. L. M. Barreto (my professor)
 * @author Bairu Li
 * @version 1.0.0
 */
public class CSHAKE implements SHAKE {
    /** Round Constant. Taken from Markku-Juhani Saarinen. (line 14 in sha.c) */
    private static final long[] keccakf_rndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    /** Round Constant. Taken from Markku-Juhani Saarinen. (line 24 in sha.c)*/
    private static final int[] keccakf_rotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14, 27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    /** Round Constant. Taken from Markku-Juhani Saarinen. (line 28 in sha.c)*/
    private static final  int[] keccakf_piln = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };
    /** Keccak rounds. */
    private static final int KECCAKF_ROUNDS = 24;
    /** For kmac instead. */
    private boolean kmac;
    /** For cshake with extension. */
    private boolean ext;

    /**
     * cSHAKE256. Method body is taken and translated from the professor's slides.
     *
     * @param X the main input bit string. Can be of any length including 0
     * @param L requested output bit-length
     * @param N function name bit-string
     * @param S customization bit-string
     */
    public static byte[] cSHAKE256(byte[] X, int L, String N, String S) {
        if ((L & 7) != 0) {
            throw new RuntimeException("Implementation restriction: output length (in bits) must be a multiple of 8");
        }
        byte[] out = new byte[L >>> 3];
        CSHAKE shake = new CSHAKE();
        SHA3Context c = new SHA3Context();
        shake.cShake256_init(c, N, S);
        shake.sha3_update(c, X, X.length);
        shake.xof(c);
        shake.shake_out(c, out, L >>> 3);
        return out; // SHAKE256(X, L) or KECCAK512(prefix || X || 00, L)
    }

    /**
     * Initializes cShake256 using definition from NIST.
     *
     * @param c the sha3 context
     * @param N function name bit-string
     * @param S customization bit-string
     */
    public void cShake256_init(SHA3Context c, String N, String S) {
        // sha3 256 has a 32 bit digest size
        sha3_init(c, 32);
        /* if cSHAKE256(X, L, "", "") = SHAKE(X, L), in other words if N and S are empty do SHAKE(X, L)
         * otherwise return
         * let padding = bytepad( encode_string(N) || encode_string(S), 136 )
         * KECCAK[512](padding || X || 00, L)
         */
        if (N.length() != 0 || S.length() != 0) {
            ext = true;
            byte[] padding = bytepad(concat(encode_string(N), encode_string(S)), 136);
            sha3_update(c, padding, padding.length);
        }
    }

    /**
     * Initializes KMACXOF256 using definition from NIST
     *
     * @param c the sha3 context
     * @param K MAC key
     * @param S customization bit-string
     */
    public void kinit256(SHA3Context c, byte[] K, String S) {
        cShake256_init(c, "KMAC", S);
        // newX = bytepad(encode_string(K), 136) || X || right_encode(0)
        // return cSHAKE256(newX, L, "KMAC", S)
        byte[] k_encoded = bytepad(encode_string(K), 136);
        sha3_update(c, k_encoded, k_encoded.length);
        kmac = true;
    }

    /**
     * Switch from absorbing to extensible squeezing.
     * Code is used from both the slides and Markku-Juhani Saarinen (line 168 in sha.c).
     *
     * @param c the sha3 context
     */
    public void xof(SHA3Context c) {
        if (kmac) {
            byte[] right_encode_0 = right_encode(0);
            sha3_update(c, right_encode_0, right_encode_0.length); // mandatory padding as per the NIST specification
        }
        // the (binary) cSHAKE suffix is 00, while the (binary) SHAKE suffix is 1111
        c.getB()[c.getPt()] ^= (byte) (ext ? 0x04 : 0x1F);
        /* big-endian interpretation (right-to-left):
         * 0x04 = 00000100 = suffix 00, right-padded with 1, right-padded with 0*
         * 0x1F = 00011111 = suffix 1111, right-padded with 1, right-padded with 0* */
        c.getB()[c.getRsiz() - 1] ^= 0x80;
        // little-endian interpretation (left-to-right):
        // 1000 0000 = suffix 1, left-padded with 0*
        keccak(c.getB());
        c.setPt(0);
    }

    // SHA3
    /**
     * Initializes the context sha3 algorithm.
     * Sha3-128 would have a md length of 16 while Sha3-256 would have a md length of 32.
     * Some of the code is taken from Markku-Juhani Saarinen (line 103 in sha.c).
     * @param c     the sha3 context
     * @param mdlen the md length
     */
    public void sha3_init(SHA3Context c, int mdlen) {
        // sets context bytes to 0
        Arrays.fill(c.getB(), (byte) 0);
        c.setMdlen(mdlen);
        c.setRsiz(200 - 2 * mdlen);
        c.setPt(0);
        ext = false;
        kmac = false;
    }

    /**
     * Updates the context with (internal state) with new input data. Repeated use of this method
     * concatenates by appending the new input data with the current context.
     * Code is taken from Markku-Juhani Saarinen (line 118 in sha.c).
     * @param c    the sha3 context
     * @param data the data
     * @param len  the length of the desired output
     */
    public void sha3_update(SHA3Context c, byte[] data, int len) {
        int j = c.getPt();

        for (int i = 0; i < len; i++) {
            c.getB()[j++] ^= data[i];

            if (j >= c.getRsiz()) {
                keccak(c.getB());
                j = 0;
            }
        }
        c.setPt(j);
    }

    /**
     * Outputs the final hash value. Code is taken from Markku-Juhani Saarinen (line 176 in sha.c).
     *
     * @param c   the sha3 context
     * @param out the output hash
     * @param len the length of the requested output
     */
    public void shake_out(SHA3Context c, byte[] out, int len) {
        int j = c.getPt();
        for (int i = 0; i < len; i++) {
            if (j >= c.getRsiz()) {
                keccak(c.getB());
                j = 0;
            }
            out[i] = c.getB()[j++];
        }
        c.setPt(j);
    }

    /**
     * {@inheritDoc}
     * <br>
     * Code is taken directly from Markku-Juhani Saarinen 's C code and translated to Java (line 11 in sha.c).
     */
    @Override
    public void keccak(byte[] b) {
        int i, j, r;
        long t;
        long[] st = new long[25];
        long[] bc = new long[5];

        // endianess conversion. this is redundant on little-endian targets
        for (i = 0, j = 0; i < 25; i++, j += 8) {
            st[i] = (((long)b[j    ] & 0xFFL)      ) | (((long)b[j + 1] & 0xFFL) <<  8) |
                    (((long)b[j + 2] & 0xFFL) << 16) | (((long)b[j + 3] & 0xFFL) << 24) |
                    (((long)b[j + 4] & 0xFFL) << 32) | (((long)b[j + 5] & 0xFFL) << 40) |
                    (((long)b[j + 6] & 0xFFL) << 48) | (((long)b[j + 7] & 0xFFL) << 56);
        }

        for (r = 0; r < KECCAKF_ROUNDS; r++) {

            // Theta
            for (i = 0; i < 5; i++)
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

            for (i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for (j = 0; j < 25; j += 5)
                    st[j + i] ^= t;
            }

            // Rho Pi
            t = st[1];
            for (i = 0; i < 24; i++) {
                j = keccakf_piln[i];
                bc[0] = st[j];
                st[j] = ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }

            //  Chi
            for (j = 0; j < 25; j += 5) {
                for (i = 0; i < 5; i++)
                    bc[i] = st[j + i];
                for (i = 0; i < 5; i++)
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }

            //  Iota
            st[0] ^= keccakf_rndc[r];
        }

        // endianess conversion. this is redundant on little-endian targets
        for (i = 0, j = 0; i < 25; i++, j += 8) {
            t = st[i];
            b[j    ] = (byte)((t      ) & 0xFF);
            b[j + 1] = (byte)((t >>  8) & 0xFF);
            b[j + 2] = (byte)((t >> 16) & 0xFF);
            b[j + 3] = (byte)((t >> 24) & 0xFF);
            b[j + 4] = (byte)((t >> 32) & 0xFF);
            b[j + 5] = (byte)((t >> 40) & 0xFF);
            b[j + 6] = (byte)((t >> 48) & 0xFF);
            b[j + 7] = (byte)((t >> 56) & 0xFF);
        }
    }

    /**
     * Used for the keccak algorithm. Markku-Juhani Saarinen (line 15 in sha.h).
     * @param x the x
     * @param y the y
     * @return the rot
     */
    private long ROTL64(long x, int y) {
        return ((x << y) | (x >>> (64 - y)));
    }

    // override methods for byte padding

    /**
     * {@inheritDoc}
     * <br>
     * Code is taken from the slides.
     */
    @Override
    public byte[] bytepad(byte[] X, int w) {
        // Validity Conditions: w > 0
        assert w > 0;
        // 1. z = left_encode(w) || X.
        byte[] w_encoded = left_encode(w);
        // NB: z.length is the smallest multiple of w that fits wenc.length + X.length
        byte[] z = new byte[w * ((w_encoded.length + X.length + w - 1) / w)];
        System.arraycopy(w_encoded, 0, z, 0, w_encoded.length);
        System.arraycopy(X, 0, z, w_encoded.length, X.length);
        // 2. (nothing to do: len(z) mod 8 = 0 in this byte-oriented implementation)
        // 3. while (len(z)/8) mod w ≠ 0: z = z || 00000000
        for (int i = w_encoded.length + X.length; i < z.length; i++) {
            z[i] = (byte) 0;
        }
        return z;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encode_string(String s) {
        // left encodes s.len * 8
        byte[] sLen_encoded = left_encode(s.length() << 3);
        byte[] s_bytes = s.getBytes();
        return concat(sLen_encoded, s_bytes);
    }

    /**
     * Encodes a byte array instead of a String.
     * @param s byte array
     * @return encoded byte array
     */
    public byte[] encode_string(byte[] s) {
        byte[] sLen_encoded = left_encode(s.length << 3);
        return concat(sLen_encoded, s);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] left_encode(int x) {
        byte[] x_encoded = new byte[(int) Math.ceil(Integer.toBinaryString(x).length() / 8D) + 1];
        int index = 1;

        // insert length of byte string before the byte string representation of x
        x_encoded[0] = (byte) (x_encoded.length - 1);

        // converts x to its byte string representation in little endian
        while(x > 0) {
            x_encoded[index++] = (byte) (x & 0xFF);
            x >>= 8;
        }

        return x_encoded;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] right_encode(int x) {
        byte[] x_encoded = new byte[(int) Math.ceil(Integer.toBinaryString(x).length() / 8D) + 1];
        int index = 0;

        // converts x to its byte string representation in little endian
        while(x > 0) {
            x_encoded[index++] = (byte) (x & 0xFF);
            x >>= 8;
        }
        // insert length of byte string after the byte string representation of x
        x_encoded[x_encoded.length - 1] = (byte) (x_encoded.length - 1);

        return x_encoded;
    }

    /**
     * Helper function to concatenate 2 byte strings a and b. b is appended on to a.
     *
     * @param a byte string a
     * @param b byte string b
     * @return byte string of a + b
     */
    public byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
