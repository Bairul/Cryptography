import java.io.PrintStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * This class contains methods to perform elliptic curve cryptography using an Edwards curve.
 * More specifically it uses Ed448-Goldilocks curve. This class can generate key pairs,
 * encrypt/decrypt and signatures.
 *
 * @author Paulo S. L. M. Barreto (my professor)
 * @author Bairu Li
 * @version 1.0.0
 */
public class EllipticCurve implements EllipticCurveCryptography {
    /**
     * Constant from specs. Any number of points n on any Edwards curve is always a multiple of 4.
     * For Ed448-Goldilocks that number is n = 4r
     */
    public static final BigInteger r = BigInteger.TWO.pow(446).
            subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

    /**
     * {@inheritDoc}
     */
    @Override
    public void generateKeyPairToFile(String passphrase, PrintStream privateKeyFile, PrintStream publicKeyFile) {
        // s <- KMACXOF256(pw, “”, 448, “SK”)
        byte[] s_0 = KMAC.KMACXOF256(passphrase.getBytes(), "".getBytes(), 448, "SK");

        // private key
        // s <- 4s (mod r)
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(s_0)).mod(r);

        // public key
        // V <- s*G
        EllipticCurvePoint V = EllipticCurvePoint.getPublicGenerator().multiplyByScalar(s);

        privateKeyFile.printf("Private Key:\n%s", s);
        publicKeyFile.printf("Public Key (point):\n%s", V);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void encrypt(byte[] message, EllipticCurvePoint publicKey, PrintStream encryptedFile) {
        // k <- Random(448)
        SecureRandom sr = new SecureRandom();
        byte[] rand448 = new byte[56]; // 448 / 8 = 56
        sr.nextBytes(rand448);
        BigInteger k = new BigInteger(rand448);

        // k <- 4k (mod r)
        k = BigInteger.valueOf(4).multiply(k).mod(r);

        // W <- k*V
        EllipticCurvePoint W = publicKey.multiplyByScalar(k);

        // Z <- k*G
        EllipticCurvePoint Z = EllipticCurvePoint.getPublicGenerator().multiplyByScalar(k);

        // (ka || ke) <- KMACXOF256(W_x, “”, 2 * 448, “PK”)
        byte[] kake = KMAC.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 896, "PK");

        // 896 / 8 = 112 byte length
        // c <- KMACXOF256(ke, “”, |m|, “PKE”) XOR m
        byte[] c = KMAC.KMACXOF256(Arrays.copyOfRange(kake, 56, 112), "".getBytes(), 8 * message.length, "PKE");
        for (int i = 0; i < message.length; i++) { // c.length == message.length
            c[i] ^= message[i];
        }

        // t <- KMACXOF256(ka, m, 448, “PKA”)
        byte[] t = KMAC.KMACXOF256(Arrays.copyOfRange(kake, 0, 56), message, 448, "PKA");

        // cryptogram (Z, c, t)
        encryptedFile.printf("Cryptogram:\n%s\n", Z);
        printHexadecimals(c, encryptedFile);
        printHexadecimals(t, encryptedFile);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(Cryptogram cryptogram, String passphrase) {
        // getting c and t from cryptogram
        byte[] c = cryptogram.getC();
        byte[] t = cryptogram.getT();

        // s <- KMACXOF256(pw, “”, 448, “SK”)
        byte[] s_0 = KMAC.KMACXOF256(passphrase.getBytes(), "".getBytes(), 448, "SK");

        // private key
        // s <- 4s (mod r)
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(s_0)).mod(r);

        // W <- s * Z
        EllipticCurvePoint W = cryptogram.getZ().multiplyByScalar(s);

        // (ka || ke) <- KMACXOF256(W_x, “”, 2 * 448, “PK”)
        byte[] kake = KMAC.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 896, "PK");

        // m <- KMACXOF256(ke, “”, |c|, “PKE”) XOR c
        byte[] m = KMAC.KMACXOF256(Arrays.copyOfRange(kake, 56, 112), "".getBytes(), 8 * c.length, "PKE");
        for (int i = 0; i < c.length; i++) { // c.length == m.length
            m[i] ^= c[i];
        }

        // t' <- KMACXOF256(ka, m, 448, “PKA”)
        byte[] t_prime = KMAC.KMACXOF256(Arrays.copyOfRange(kake, 0, 56), m, 448, "PKA");

        // m || (t=t')
        return concat(m, Arrays.equals(t, t_prime) ? new byte[] {1} : new byte[] {0});
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void fileSignature(byte[] message, String passphrase, PrintStream outFile) {
        // s <- KMACXOF256(pw, “”, 448, “SK”)
        byte[] s_0 = KMAC.KMACXOF256(passphrase.getBytes(), "".getBytes(), 448, "SK");

        // private key
        // s <- 4s (mod r)
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(s_0)).mod(r);

        // k <- KMACXOF256(s, m, 448, “N”)
        byte[] k_0 = KMAC.KMACXOF256(s.toByteArray(), message, 448, "N");

        // k <- 4k (mod r)
        BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger(k_0)).mod(r);

        // U <- k * G
        EllipticCurvePoint U = EllipticCurvePoint.getPublicGenerator().multiplyByScalar(k);

        // h <- KMACXOF256(U_x, m, 448, “T”)
        byte[] h_0 = KMAC.KMACXOF256(U.getX().toByteArray(), message, 448, "T");
        BigInteger h = new BigInteger(1, h_0);

        // z <- (k - hs) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(r);

        // signature: (h, z)
        outFile.printf("Signature:\n%s\n", h);
        outFile.printf("%s", z);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verifySignature(byte[] message, Signature signature, EllipticCurvePoint publicKey) {
        BigInteger h = signature.getH();
        BigInteger z = signature.getZ();

        /* Proof of correctness:
         * let k = z + hs
         * let z = k - hs
         * U <- k * G (definition)
         * V <- s * G (public key)
         *
         * U <- (z + hs) * G
         * using theorem that has been tested valid
         * U <- (z + hs) * G = (z * G) + (hs * G)
         * using theorem that has been tested valid
         * U <- (z + hs) * G = (z * G) + h * (s * G)
         * U <- (z + hs) * G = (z * G) + (h * V)
         * U <- k * G        = (z * G) + (h * V)
         */

        // U <- (z * G) + (h * V)
        EllipticCurvePoint U = EllipticCurvePoint.getPublicGenerator().multiplyByScalar(z)
                               .add(publicKey.multiplyByScalar(h));

        // h' <- KMACXOF256(U_x, m, 448, “T”)
        byte[] h_prime_0 = KMAC.KMACXOF256(U.getX().toByteArray(), message, 448, "T");
        BigInteger h_prime = new BigInteger(1, h_prime_0);

        // accept iff h' = h
        return h.equals(h_prime);
    }

    /**
     * Helper function to concatenate 2 byte strings a and b. b is appended on to a.
     *
     * @param a byte string a
     * @param b byte string b
     * @return byte string of a + b
     */
    private byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    /** Hexadecimal values in char array. */
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Prints the hexadecimals of a byte array to a output stream.
     * This method is taken from <a href="https://stackoverflow.com/questions/9655181/java-convert-a-byte-array-to-a-hex-string">Stackoverflow</a>.
     * @param bytes the byte array
     * @param out   the output
     */
    public static void printHexadecimals(byte[] bytes, PrintStream out) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        out.println(new String(hexChars));
    }
}
