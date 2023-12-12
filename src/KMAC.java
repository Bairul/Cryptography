import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Class for encryption and decryption using a MAC.
 *
 * @author Paulo S. L. M. Barreto (my professor)
 * @author Bairu Li
 */
public final class KMAC {
    /**
     * Compute KMACXOF256. Method body is taken from the professor's slides.
     *
     * @param K MAC key
     * @param X data to be hashed
     * @param L requested output bit-length
     * @param S customization bit-string
     * @return the desired MAC tag
     */
    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, String S) {
        // Validity Conditions: len(K) < 2^2040 and 0 ≤ L and len(S) < 2^2040
        if ((L & 7) != 0) {
            throw new RuntimeException("Implementation restriction: output length (in bits) must be a multiple of 8");
        }
        byte[] val = new byte[L >>> 3];
        CSHAKE shake = new CSHAKE();
        SHA3Context c = new SHA3Context();
        // begin kmac
        shake.kinit256(c, K, S);
        shake.sha3_update(c, X, X.length);
        shake.xof(c);
        shake.shake_out(c, val, L >>> 3);
        return val; // SHAKE256(X, L) or KECCAK512(prefix || X || 00, L)
    }
    /**
     * Encryption of a plaintext message in byte strings and a given passphrase.
     * Code is written by translating the pseudocode given by the professor in the project specification.
     *
     * @param message    message to encrypt as byte array
     * @param passphrase passphrase string
     * @return symmetric cryptogram z || c || t
     */
    public static byte[] encrypt(byte[] message, String passphrase) {
        // z <- Random(512)
        SecureRandom sr = new SecureRandom();
        byte[] z = new byte[64];
        sr.nextBytes(z);

        // (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] keka = KMACXOF256(ByteStringUtil.concat(z, passphrase.getBytes()), "".getBytes(), 1024, "S");

        // 1024 / 8 = 128 byte length
        // c <- KMACXOF256(ke, “”, |m|, “SKE”) XOR m
        byte[] c = KMACXOF256(Arrays.copyOfRange(keka, 0, 64), "".getBytes(), 8 * message.length, "SKE");
        for (int i = 0; i < message.length; i++) { // c.length == message.length
            c[i] ^= message[i];
        }

        // t <- KMACXOF256(ka, m, 512, “SKA”)
        byte[] t = KMACXOF256(Arrays.copyOfRange(keka, 64, 128), message, 512, "SKA");

        // symmetric cryptogram (z, c, t)
        return ByteStringUtil.concat(ByteStringUtil.concat(z, c), t);
    }

    /**
     * Decryption ciphertext cryptogram using the passphrase.
     * Code is written by translating the pseudocode given by the professor.
     *
     * @param cryptogram the ciphertext as byte array
     * @param passphrase passphrase string
     * @return the plaintext message as byte string || 0 or 1 depending on if t = t'
     */
    public static byte[] decrypt(byte[] cryptogram, String passphrase) {
        // z is concatenated first with a byte length of 64
        byte[] z = Arrays.copyOfRange(cryptogram, 0, 64);
        // t is concatenated last with a byte length of 64. (512 bits / 8)
        byte[] t = Arrays.copyOfRange(cryptogram, cryptogram.length - 64, cryptogram.length);
        // c is found in the middle of z and t
        byte[] c = Arrays.copyOfRange(cryptogram,64, cryptogram.length - 64);

        // (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] keka = KMACXOF256(ByteStringUtil.concat(z, passphrase.getBytes()), "".getBytes(), 1024, "S");

        // m <- KMACXOF256(ke, “”, |c|, “SKE”) XOR c
        byte[] m = KMACXOF256(Arrays.copyOfRange(keka, 0, 64), "".getBytes(), 8 * c.length, "SKE");
        for (int i = 0; i < c.length; i++) { // c.length == m.length
            m[i] ^= c[i];
        }

        // t' <- KMACXOF256(ka, m, 512, “SKA”)
        byte[] t_prime = KMACXOF256(Arrays.copyOfRange(keka, 64, 128), m, 512, "SKA");

        // m || (t=t')
        return ByteStringUtil.concat(m, Arrays.equals(t, t_prime) ? new byte[] {1} : new byte[] {0});
    }
}
