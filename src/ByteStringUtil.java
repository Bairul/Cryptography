import java.io.PrintStream;

public final class ByteStringUtil {
    /** Hexadecimal values in char array. */
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Concatenate 2 byte strings a and b. b is appended on to a.
     *
     * @param theA byte string a
     * @param theB byte string b
     * @return byte string of a + b
     */
    public static byte[] concat(final byte[] theA, final byte[] theB) {
        byte[] c = new byte[theA.length + theB.length];
        System.arraycopy(theA, 0, c, 0, theA.length);
        System.arraycopy(theB, 0, c, theA.length, theB.length);
        return c;
    }

    /**
     * Prints the hexadecimals of a byte array to a output stream.
     * This method is taken from <a href="https://stackoverflow.com/questions/9655181/java-convert-a-byte-array-to-a-hex-string">Stackoverflow</a>.
     *
     * @param theBytes the byte array
     * @param theOut   the output
     */
    public static void printHexadecimals(final byte[] theBytes, final PrintStream theOut) {
        char[] hexChars = new char[theBytes.length * 2];
        for (int j = 0; j < theBytes.length; j++) {
            int v = theBytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        theOut.println(new String(hexChars));
    }

    /**
     * Converts a string of hexadecimals to a byte array.
     * @param hexString the hex string
     * @return byte array of the hex string
     */
    public static byte[] hexToBytes(String hexString) {
        byte[] b = new byte[hexString.length() / 2];

        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) ((Character.digit(hexString.charAt(2 * i), 16) << 4)
                    + Character.digit(hexString.charAt(2 * i + 1), 16));
        }

        return b;
    }
}
