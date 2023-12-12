/**
 * Class for storing the Sha3 states. Code is taken from Markku-Juhani Saarinen (line 19 in sha.h)
 *
 * @author Markku-Juhani Saarinen (<a href="https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.h" >Their C code implementation</a>)
 */
public final class SHA3Context {
    /** State context for 8-bit bytes. Used for processing the input data. */
    private byte[] b;
    /** The position within the data being hashed. */
    private int pt;
    /** The rate size. */
    private int rsiz;
    /** The requested length of the hash output in bits. */
    private int mdlen;

    /**
     * Constructs the context for hashing.
     */
    public SHA3Context() {
        // Initialize the members as needed
        b = new byte[200];

        pt = 0;
        rsiz = 0;
        mdlen = 0;
    }

    // getters
    /**
     * Gets the bytes.
     * @return byte string
     */
    public byte[] getB() {
        return b;
    }

    /**
     * Gets the pt.
     * @return pt
     */
    public int getPt() {
        return pt;
    }

    /**
     * Gets the rsiz.
     * @return rsiz
     */
    public int getRsiz() {
        return rsiz;
    }

    // setters

    /**
     * Sets the pt.
     * @param pt value for pt
     */
    public void setPt(int pt) {
        this.pt = pt;
    }

    /**
     * Sets the rsiz.
     * @param rsiz value for rsiz
     */
    public void setRsiz(int rsiz) {
        this.rsiz = rsiz;
    }

    /**
     * Sets the mdlen.
     * @param mdlen value for mdlen
     */
    public void setMdlen(int mdlen) {
        this.mdlen = mdlen;
    }
}
