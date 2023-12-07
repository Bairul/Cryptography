import java.io.File;
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
    public byte[] encrypt(byte[] message, EllipticCurvePoint publicKey) {
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
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(byte[] cryptogram, String passphrase) {
        // s <- KMACXOF256(pw, “”, 448, “SK”)


        // s <- 4s (mod r)


        // W <- s * Z

        // (ka || ke) <- KMACXOF256(W_x, “”, 2 * 448, “PK”)

        // m <- KMACXOF256(ke, “”, |c|, “PKE”) XOR c

        // t' <- KMACXOF256(ka, m, 448, “PKA”)

        // accept iff t' = t
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void fileSignature(byte[] message, String passphrase, PrintStream outFile) {
        // s <- KMACXOF256(pw, “”, 448, “SK”)
        byte[] s_0 = KMAC.KMACXOF256(passphrase.getBytes(), "".getBytes(), 448, "SK");

        // s <- 4s (mod r)
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(s_0)).mod(r);

        // k <- KMACXOF256(s, m, 448, “N”)
        byte[] k_0 = KMAC.KMACXOF256(s.toByteArray(), message, 448, "N");

        // k <- 4k (mod r)
        BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger(k_0)).mod(r);

        // U <- k * G
        EllipticCurvePoint U = EllipticCurvePoint.getPublicGenerator().multiplyByScalar(k);
        System.out.println(U);

        // h <- KMACXOF256(U_x, m, 448, “T”)
        byte[] h_0 = KMAC.KMACXOF256(U.getX().toByteArray(), message, 448, "T");
        BigInteger h = new BigInteger(h_0);

        // z <- (k - hs) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(r);

        // signature: (h, z)
        outFile.printf("%s\n", h);
        outFile.printf("%s", z);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verifySignature(byte[] message, Signature signature, EllipticCurvePoint publicKey) {
        BigInteger z = signature.getZ();
        BigInteger h = signature.getH();

        // U <- z * G + h * V
        EllipticCurvePoint U = EllipticCurvePoint.getPublicGenerator().multiplyByScalar(z).add(publicKey.multiplyByScalar(h));
        System.out.println(U);

        // h' <- KMACXOF256(U_x, m, 448, “T”)
        byte[] h_prime = KMAC.KMACXOF256(U.getX().toByteArray(), message, 448, "T");

        // accept iff h' = h
        return Arrays.equals(h.toByteArray(), h_prime);
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
