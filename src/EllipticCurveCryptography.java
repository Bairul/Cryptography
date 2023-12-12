import java.io.PrintStream;

/**
 * Interface for defining the required methods for DHIES (Diffie-Hellman Integrated Encryption Scheme).
 * The definitions of all the provided methods are from the
 * project specification paper.
 *
 * @author Paulo S. L. M. Barreto (my professor)
 * @author Bairu Li
 * @version 1.0.0
 */
public interface EllipticCurveCryptography {
    /**
     * Generate an elliptic key pair from a given passphrase and write the
     * public key to a file.
     *
     * @param passphrase     the passphrase for the key pair
     * @param publicKeyFile  the file for outputting the public key as a printStream
     * @param privateKeyFile the file for outputting the private key as a printStream
     */
    void generateKeyPairToFile(String passphrase, PrintStream privateKeyFile, PrintStream publicKeyFile);

    /**
     * Encrypt a data file under a given elliptic public key file and write
     * the ciphertext to a file.
     *
     * @param message       message to encrypt as byte array
     * @param publicKey     the public key as an elliptic curve point
     * @param encryptedFile the file for outputting the cryptogram Z || c || t
     */
    void encrypt(byte[] message, EllipticCurvePoint publicKey, PrintStream encryptedFile);

    /**
     * Decrypt a given elliptic-encrypted file from a given password and
     * write the decrypted data to a file.
     *
     * @param cryptogram     the ciphertext in a cryptogram
     * @param passphrase     the passphrase from the key pair
     * @return the plaintext message as byte string || 0 or 1 depending on if t = t'
     */
    byte[] decrypt(Cryptogram cryptogram, String passphrase);

    /**
     * Sign a given file from a given password and write the signature to
     * a file.
     *
     * @param message    message to encrypt as byte array
     * @param passphrase the passphrase from the key pair
     * @param dataFile   the data file
     *
     */
    void fileSignature(byte[] message, String passphrase, PrintStream dataFile);

    /**
     * Verify a given data file and its signature file under a given public
     * key file.
     *
     * @param message   the message
     * @param signature the signature
     * @param publicKey the public key
     * @return true if verified and false otherwise
     */
    boolean verifySignature(byte[] message, Signature signature, EllipticCurvePoint publicKey);
}
