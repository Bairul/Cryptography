/**
 * Interface for defining required methods for cSHAKE.
 * The definitions of the provided methods are from
 * <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf" >NIST</a>
 */
public interface SHAKE {
    /**
     * Function prepends an encoding of the integer w to an input string
     * X, then pads the result with 0s until it is a byte string whose
     * length in bytes us a multiple of w.
     * <br><br>
     * Validity Conditions: w > 0
     *
     * @param x the String input
     * @param w the block size
     */
    byte[] bytepad(byte[] x, int w);

    /**
     * Function is used to encode bit strings in a way that may be parsed
     * unambiguously from the beginning of the string, s.
     * <br><br>
     * Validity Conditions: 0 <= len(s) < 2^2024
     *
     * @param s the String input
     */
    byte[] encode_string(String s);

    /**
     * Encodes the integer x as a byte String in a way that can be unambiguously
     * parsed from the <b>beginning</b> of the string by inserting the length of
     * the byte string <b>before</b> the byte string representation of x
     * <br><br>
     * Validity Conditions: 0 <= x < 2^2040
     *
     * @param x the integer to encode
     */
    byte[] left_encode(int x);

    /**
     * Encodes the integer x as a byte string in a way that can be unambiguously
     * parsed from the <b>end</b> of the string by inserting the length of the
     * byte string <b>after</b> the byte string representation of x
     * <br><br>
     * Validity Conditions: 0 <= x < 2^2040
     *
     * @param x
     */
    byte[] right_encode(int x);

    /**
     * The core algorithm.
     *
     * @param c the
     */
    void keccak(byte[] c);
}
