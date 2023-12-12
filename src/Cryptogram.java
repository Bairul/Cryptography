/**
 * Class to store the values of the cryptogram (Z, c, t).
 *
 * @author Bairu Li
 * @version 1.0.0
 */
public final class Cryptogram {
    /** The c as a byte array. */
    private byte[] c;
    /** The t as a byte array. */
    private byte[] t;
    /** The Z as a elliptic curve point. */
    private EllipticCurvePoint Z;

    /**
     * Constructs the cryptogram.
     *
     * @param Z the elliptic curve point
     * @param c the c byte array
     * @param t the t byte array
     */
    public Cryptogram(EllipticCurvePoint Z, byte[] c, byte[] t) {
        // for better security, it is probably best to do a deep copy instead
        this.Z = Z;
        this.c = c;
        this.t = t;
    }

    /**
     * Getter for Z.
     * @return the elliptic curve point Z
     */
    EllipticCurvePoint getZ() { return Z; }

    /**
     * Getter for c.
     * @return the byte array c
     */
    byte[] getC() { return c; }

    /**
     * Getter for t.
     * @return the byte array t
     */
    byte[] getT() { return t; }
}
