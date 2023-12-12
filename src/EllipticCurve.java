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
public final class EllipticCurve implements EllipticCurveCryptography {
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
    public void generateKeyPairToFile(final String thePassphrase, final PrintStream thePrivateKeyFile, final PrintStream thePublicKeyFile) {
        // s <- KMACXOF256(pw, “”, 448, “SK”)
        byte[] s_0 = KMAC.KMACXOF256(thePassphrase.getBytes(), "".getBytes(), 448, "SK");

        // private key
        // s <- 4s (mod r)
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(s_0)).mod(r);

        // public key
        // V <- s*G
        EllipticCurvePoint V = EllipticCurvePoint.getPublicGenerator().multiplyByScalar(s);

        thePrivateKeyFile.printf("Private Key:\n%s", s);
        thePublicKeyFile.printf("Public Key (point):\n%s", V);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void encrypt(final byte[] theMessage, final EllipticCurvePoint thePublicKey, final PrintStream theEncryptedFile) {
        // k <- Random(448)
        SecureRandom sr = new SecureRandom();
        byte[] rand448 = new byte[56]; // 448 / 8 = 56
        sr.nextBytes(rand448);
        BigInteger k = new BigInteger(rand448);

        // k <- 4k (mod r)
        k = BigInteger.valueOf(4).multiply(k).mod(r);

        // W <- k*V
        EllipticCurvePoint W = thePublicKey.multiplyByScalar(k);

        // Z <- k*G
        EllipticCurvePoint Z = EllipticCurvePoint.getPublicGenerator().multiplyByScalar(k);

        // (ka || ke) <- KMACXOF256(W_x, “”, 2 * 448, “PK”)
        byte[] kake = KMAC.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 896, "PK");

        // 896 / 8 = 112 byte length
        // c <- KMACXOF256(ke, “”, |m|, “PKE”) XOR m
        byte[] c = KMAC.KMACXOF256(Arrays.copyOfRange(kake, 56, 112), "".getBytes(), 8 * theMessage.length, "PKE");
        for (int i = 0; i < theMessage.length; i++) { // c.length == message.length
            c[i] ^= theMessage[i];
        }

        // t <- KMACXOF256(ka, m, 448, “PKA”)
        byte[] t = KMAC.KMACXOF256(Arrays.copyOfRange(kake, 0, 56), theMessage, 448, "PKA");

        // cryptogram (Z, c, t)
        theEncryptedFile.printf("Cryptogram:\n%s\n", Z);
        ByteStringUtil.printHexadecimals(c, theEncryptedFile);
        ByteStringUtil.printHexadecimals(t, theEncryptedFile);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(final Cryptogram theCryptogram, final String thePassphrase) {
        // getting c and t from cryptogram
        byte[] c = theCryptogram.getC();
        byte[] t = theCryptogram.getT();

        // s <- KMACXOF256(pw, “”, 448, “SK”)
        byte[] s_0 = KMAC.KMACXOF256(thePassphrase.getBytes(), "".getBytes(), 448, "SK");

        // private key
        // s <- 4s (mod r)
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(s_0)).mod(r);

        // W <- s * Z
        EllipticCurvePoint W = theCryptogram.getZ().multiplyByScalar(s);

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
        return ByteStringUtil.concat(m, Arrays.equals(t, t_prime) ? new byte[] {1} : new byte[] {0});
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void fileSignature(final byte[] theMessage, final String thePassphrase, final PrintStream theOutFile) {
        // s <- KMACXOF256(pw, “”, 448, “SK”)
        byte[] s_0 = KMAC.KMACXOF256(thePassphrase.getBytes(), "".getBytes(), 448, "SK");

        // private key
        // s <- 4s (mod r)
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(s_0)).mod(r);

        // k <- KMACXOF256(s, m, 448, “N”)
        byte[] k_0 = KMAC.KMACXOF256(s.toByteArray(), theMessage, 448, "N");

        // k <- 4k (mod r)
        BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger(k_0)).mod(r);

        // U <- k * G
        EllipticCurvePoint U = EllipticCurvePoint.getPublicGenerator().multiplyByScalar(k);

        // h <- KMACXOF256(U_x, m, 448, “T”)
        byte[] h_0 = KMAC.KMACXOF256(U.getX().toByteArray(), theMessage, 448, "T");
        BigInteger h = new BigInteger(1, h_0);

        // z <- (k - hs) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(r);

        // signature: (h, z)
        theOutFile.printf("Signature:\n%s\n", h);
        theOutFile.printf("%s", z);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verifySignature(final byte[] theMessage, final Signature theSignature, final EllipticCurvePoint thePublicKey) {
        BigInteger h = theSignature.getH();
        BigInteger z = theSignature.getZ();

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
                               .add(thePublicKey.multiplyByScalar(h));

        // h' <- KMACXOF256(U_x, m, 448, “T”)
        byte[] h_prime_0 = KMAC.KMACXOF256(U.getX().toByteArray(), theMessage, 448, "T");
        BigInteger h_prime = new BigInteger(1, h_prime_0);

        // accept iff h' = h
        return h.equals(h_prime);
    }
}
