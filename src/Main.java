import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class Main {
    /** Hexadecimal values in char array. */
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Main method.
     * @param args input/output files and passphrase
     */
    public static void main(final String[] args) {
        // must have 3 arguments containing the input file name, output file name, and passphrase respectively
        if (args.length != 3) {
            System.out.println("Incorrect argument format. Please refer to the manuel. ");
            return;
        }
        // initializes the input and output
        Scanner inputFile = null;
        PrintStream out = null;
        try {
            if (!args[0].equals("."))
                inputFile = new Scanner(new File(args[0]));
        } catch (FileNotFoundException e) {
            System.out.println("Sorry, cannot find input file \"" + args[0] + "\". Please try again.");
            return;
        }

        // initializes variables for the application
        final EllipticCurve ec = new EllipticCurve();
        final Scanner scan = new Scanner(System.in);
        final String passphrase = args[2];
        byte[] data = null;
        OptionSelect opt = OptionSelect.UNKNOWN;
        String userInput;

        // start
        initTerminal();

        // select options
        while (opt == OptionSelect.UNKNOWN) {
            userInput = scan.nextLine();
            if (userInput.equals("q")) {
                quitTerminal(out, scan, inputFile);
                return;
            }
            opt = menuOptions(userInput);
        }
        if (!(opt == OptionSelect.HASH_INPUT || opt == OptionSelect.MAC_INPUT) && args[0].equals(".")) {
            System.out.println("No input file was found. Cannot continue.");
            quitTerminal(out, scan, inputFile);
            return;
        }
        if (opt != OptionSelect.DECRYPT_FILE_EC && opt != OptionSelect.DECRYPT_FILE && opt != OptionSelect.HASH_INPUT && opt != OptionSelect.MAC_INPUT) {
            data = getDataFromFile(inputFile);
        }
        if (opt != OptionSelect.VERIFY_FILE) {
            try {
                out = new PrintStream(args[1]);
            } catch (FileNotFoundException e) {
                System.out.println("Sorry, cannot find output file \"" + args[1] + "\". Please try again.");
                return;
            }
        }

        // options
        switch (opt) {
            case HASH_FILE -> {
                // computing a cryptographic hash h of a byte array data
                // h <- KMACXOF256(“”, data, 512, “D”)
                printHexadecimals(KMAC.KMACXOF256("".getBytes(), data, 512, "D"), out);
                System.out.println("Hash complete. See output file for the hash in hex.");
            }
            case HASH_INPUT -> {
                System.out.println("Enter the data to be hashed.");
                // change input data to be from the terminal
                inputFile = new Scanner(scan.nextLine());
                data = getDataFromFile(inputFile);
                // h <- KMACXOF256(“”, data, 512, “D”)
                printHexadecimals(KMAC.KMACXOF256("".getBytes(), data, 512, "D"), out);
                System.out.println("Hash complete. See output file for the hash in hex.");
            }
            case MAC_FILE -> {
                // computing an authentication tag t of a byte array data under passphrase
                // t <- KMACXOF256(passphrase, data, 512, “T”)
                printHexadecimals(KMAC.KMACXOF256(new CSHAKE().encode_string(passphrase), data, 512, "T"), out);
                System.out.println("MAC complete. See output file for the MAC in hex.");
            }
            case MAC_INPUT -> {
                System.out.println("Enter the data for the MAC.");
                // change input data to be from the terminal
                inputFile = new Scanner(scan.nextLine());
                data = getDataFromFile(inputFile);
                // t <- KMACXOF256(passphrase, data, 512, “T”)
                printHexadecimals(KMAC.KMACXOF256(new CSHAKE().encode_string(passphrase), data, 512, "T"), out);
                System.out.println("MAC complete. See output file for the MAC in hex.");
            }
            case ENCRYPT_FILE -> {
                printHexadecimals(KMAC.encrypt(data, passphrase), out);
                System.out.println("Encryption Complete. See output file for the encryption.");
            }
            case DECRYPT_FILE -> {
                if (!inputFile.hasNext()) {
                    System.out.println("Oh no! Decryption failed. ");
                    break;
                }
                data = hexToBytes(inputFile.nextLine());
                byte[] dec;
                try {
                    dec = KMAC.decrypt(data, passphrase);
                } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
                    System.out.println("Oh no! Decryption failed. Input has been tampered.");
                    break;
                }
                // removes the last bit because it just encodes whether t = t'
                byte t_equals_t_prime = dec[dec.length - 1];
                dec = Arrays.copyOf(dec, dec.length - 1);
                // accept if and only if t = t'
                if (t_equals_t_prime == 1) {
                    System.out.println("Decryption Complete. See output file for the decryption.");
                    out.println(new String(dec));
                } else {
                    System.out.println("Oh no! Decryption failed. ");
                }
            }
            case GEN_KEYPAIR -> {
                PrintStream in_ec;
                try {
                    in_ec = new PrintStream(args[0]);
                } catch (FileNotFoundException e) {
                    System.out.println("Sorry, cannot find input file \"" + args[0] + "\". Please try again.");
                    break;
                }
                ec.generateKeyPairToFile(passphrase, in_ec, out);
                in_ec.close();
                System.out.println("Generation Success.\nYour private key is stored in \"" + args[0] +"\".\nYour public key is stored in \"" + args[1] + "\"");
            }
            case ENCRYPT_FILE_EC -> {
                Scanner pkFile;
                try {
                    pkFile = new Scanner(new File(args[2]));
                    if (!pkFile.hasNext()) {
                        System.out.println("Warning! Empty public key file \"" + args[2] + "\".");
                        break;
                    }
                } catch (FileNotFoundException e) {
                    System.out.println("Sorry, cannot find public key file \"" + args[2] + "\". Please try again.");
                    break;
                }
                pkFile.nextLine();
                EllipticCurvePoint pk;
                try {
                    pk = new EllipticCurvePoint(new BigInteger(pkFile.nextLine()), new BigInteger(pkFile.nextLine()));
                } catch (NoSuchElementException | NumberFormatException e) {
                    System.out.println("Oh no! Public Key has been tampered.");
                    break;
                }

                ec.encrypt(data, pk, out);
                System.out.println("Encryption Complete. See \"" + args[1] + "\" file for the cryptogram.");
                pkFile.close();
            }
            case DECRYPT_FILE_EC -> {
                if (!inputFile.hasNext()) {
                    System.out.println("Oh no! Decryption failed. Empty cryptogram file \"" + args[0] + "\"");
                    break;
                }
                inputFile.nextLine();
                EllipticCurvePoint Z;
                try {
                    Z = new EllipticCurvePoint(new BigInteger(inputFile.nextLine()), new BigInteger(inputFile.nextLine()));
                } catch (NoSuchElementException | NumberFormatException e) {
                    System.out.println("Oh no! Cryptogram file has been tampered.");
                    break;
                }
                byte[] c;
                try {
                    c = hexToBytes(inputFile.nextLine());
                } catch (NoSuchElementException | IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
                    System.out.println("Oh no! Cryptogram file has been tampered.");
                    break;
                }
                byte[] t;
                try {
                    t = hexToBytes(inputFile.nextLine());
                } catch (NoSuchElementException | IllegalArgumentException | ArrayIndexOutOfBoundsException e) {
                    System.out.println("Oh no! Cryptogram file has been tampered.");
                    break;
                }
                Cryptogram crypt = new Cryptogram(Z, c, t);

                byte[] dec = ec.decrypt(crypt, passphrase);
                // removes the last bit because it just encodes whether t = t'
                byte t_equals_t_prime = dec[dec.length - 1];
                dec = Arrays.copyOf(dec, dec.length - 1);
                // accept if and only if t = t'
                if (t_equals_t_prime == 1) {
                    System.out.println("Decryption Complete. See \"" + args[1] + "\" file for the decryption.");
                    out.println(new String(dec));
                } else {
                    System.out.println("Oh no! Decryption failed.");
                }
            }
            case SIGN_FILE -> {
                ec.fileSignature(data, passphrase, out);
                System.out.println("Signing Complete. See \"" + args[1] + "\" file for the signature.");
            }
            case VERIFY_FILE -> {
                Scanner sigFile;
                Scanner pkFile;
                try {
                    sigFile = new Scanner(new File(args[1]));
                    if (!sigFile.hasNext()) {
                        System.out.println("Warning! Empty signature file \"" + args[1] + "\".");
                        break;
                    }
                } catch (FileNotFoundException e) {
                    System.out.println("Sorry, cannot find signature file \"" + args[1] + "\". Please try again.");
                    break;
                }
                try {
                    pkFile = new Scanner(new File(args[2]));
                    if (!pkFile.hasNext()) {
                        System.out.println("Warning! Empty public key file \"" + args[2] + "\".");
                        break;
                    }
                } catch (FileNotFoundException e) {
                    System.out.println("Sorry, cannot find public key file \"" + args[2] + "\". Please try again.");
                    break;
                }
                sigFile.nextLine();
                Signature sig;
                try {
                    sig = new Signature(new BigInteger(sigFile.nextLine()), new BigInteger(sigFile.nextLine()));
                } catch (NoSuchElementException | NumberFormatException e) {
                    System.out.println("Oh no! Signature has been tampered.");
                    break;
                }
                EllipticCurvePoint pk;
                pkFile.nextLine();
                try {
                    pk = new EllipticCurvePoint(new BigInteger(pkFile.nextLine()), new BigInteger(pkFile.nextLine()));
                } catch (NoSuchElementException | NumberFormatException e) {
                    System.out.println("Oh no! Public Key has been tampered.");
                    break;
                }

                if (ec.verifySignature(data, sig, pk)) {
                    System.out.println("Signature Verified.");
                } else {
                    System.out.println("Rejected! Signature is not verified.");
                }
                pkFile.close();
                sigFile.close();
            }
        }

        quitTerminal(out, scan, inputFile);
    }

    /**
     * Gets the option from user input.
     * @param userInput user input string
     * @return option selection as a OptionSelect
     */
    private static OptionSelect menuOptions(String userInput) {
        if (userInput == null) return OptionSelect.UNKNOWN;

        try {
            int num = Integer.parseInt(userInput);
            switch (num) {
                case (1)  -> { return OptionSelect.HASH_FILE;       }
                case (2)  -> { return OptionSelect.HASH_INPUT;      }
                case (3)  -> { return OptionSelect.MAC_FILE;        }
                case (4)  -> { return OptionSelect.MAC_INPUT;       }
                case (5)  -> { return OptionSelect.ENCRYPT_FILE;    }
                case (6)  -> { return OptionSelect.DECRYPT_FILE;    }
                case (7)  -> { return OptionSelect.GEN_KEYPAIR;     }
                case (8)  -> { return OptionSelect.ENCRYPT_FILE_EC; }
                case (9)  -> { return OptionSelect.DECRYPT_FILE_EC; }
                case (10) -> { return OptionSelect.SIGN_FILE;       }
                case (11) -> { return OptionSelect.VERIFY_FILE;     }
                default -> {
                    System.out.println("Illegal input. Please try again. ");
                    return OptionSelect.UNKNOWN;
                }
            }
        } catch (NumberFormatException e) {
            System.out.println("Illegal input. Please try again. ");
            return OptionSelect.UNKNOWN;
        }
    }

    /**
     * Landing text and menu options.
     */
    private static void initTerminal() {
        System.out.println("==================================================\n=                    Welcome!                    =\n==================================================");
        System.out.println("\nThis application computes cryptographic hash using KMACXOF256\nand elliptic curve Diffie-Hellman.");
        System.out.println("To get started, here are the menu options. \nIf you wish to exit the application, enter \"q\"\n");
        System.out.println("Menu Options: (Enter a number):");
        System.out.println("Part 1: Using KMAC");
        System.out.println("1) Hash data from input file\n2) Hash data from terminal input\n3) Create MAC from input file\n4) Create MAC from terminal input");
        System.out.println("5) Encrypt the input file\n6) Decrypt the input file");
        System.out.println("\nPart 2: Using Elliptic Curve");
        System.out.println("7) Generate a Key Pair using passphrase\n8) Encrypt the input file using public key\n9) Decrypt the input file using passphrase");
        System.out.println("10) Sign input file using passphrase\n11) Verify input file using signature and public key");
    }

    /**
     * Closes all input and output and shows exit text.
     * @param out      output file
     * @param scanners input files
     */
    private static void quitTerminal(PrintStream out, Scanner... scanners) {
        for (Scanner s : scanners) {
            if (s != null) s.close();
        }
        System.out.println("==================================================\n=               See you next time.               =\n==================================================");
        if (out != null) out.close();
    }

    /**
     * Gets data as a byte string from a file.
     * <br>
     * Example:
     * <li>0x 00 01 02</li>
     * @param file the input file
     * @return byte array containing the contents of the input file
     */
    private static byte[] getDataFromFile(Scanner file) {
        if (!file.hasNext()) {
            return "".getBytes();
        }
        StringBuilder fileConents = new StringBuilder();

        while (file.hasNextLine()) {
            fileConents.append(file.nextLine()).append("\n");
        }

        return fileConents.toString().getBytes();
    }

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
