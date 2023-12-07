import java.math.BigInteger;

public final class Signature {
    private BigInteger h;
    private BigInteger z;

    public Signature(BigInteger h, BigInteger z) {
        this.h = h;
        this.z = z;
    }

    BigInteger getH() { return this.h; }
    BigInteger getZ() { return this.z; }
}
