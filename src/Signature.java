import java.math.BigInteger;

/**
 * Class for holding the signature (h, z).
 *
 * @author Bairu Li
 * @version 1.0.0
 */
public final class Signature {
    /** The h as a bigInt.*/
    private BigInteger h;
    /** The z as a bigInt.*/
    private BigInteger z;

    /**
     * Constructs the signature.
     * @param h the hash
     * @param z the z
     */
    public Signature(BigInteger h, BigInteger z) {
        this.h = h;
        this.z = z;
    }

    /**
     * Getter for h.
     * @return h as a big int
     */
    BigInteger getH() { return h; }

    /**
     * Getter for z.
     * @return z as a big int
     */
    BigInteger getZ() { return z; }
}
