import java.math.BigInteger;
import java.util.Objects;

/**
 * The elliptic curve that this class implements is known as Ed448-Goldilocks curve,
 * also called Edwards curve. Contains methods of scalar multiplication, and point addition.
 *
 * @author Paulo S. L. M. Barreto (my professor)
 * @author Bairu Li
 * @version 1.0.0
 */
public class EllipticCurvePoint {
    // constants for the curve equation
    /** The prime constant. 2^448 − 2^224 − 1. */
    private static final BigInteger p = BigInteger.valueOf(2).pow(448).subtract(BigInteger.valueOf(2).pow(224)).subtract(BigInteger.ONE);
    /** The definition constant. */
    private static final BigInteger d = BigInteger.valueOf(-39081);

    /** The x coordinate on the elliptic edwards curve. */
    private final BigInteger x;
    /** The y coordinate on the elliptic edwards curve. */
    private final BigInteger y;

    /**
     * Constructs edwards curve point at given an x and y coordinate.
     * @param theX the x as a BigInteger
     * @param theY the y as a BigInteger
     */
    public EllipticCurvePoint(final BigInteger theX, final BigInteger theY) {
        x = theX;
        y = theY;
    }

    /**
     * Constructs edwards curve point at a given y coordinate and the least significant bit of x.
     * @param theY                 the y as a BigInteger
     * @param leastSignificantBitX the least significant bit of x as a boolean (true: 1, false: 0)
     */
    public EllipticCurvePoint(final BigInteger theY, boolean leastSignificantBitX) {
        y = theY;

        // x = ±√( (1 − y^2) / (1 + 39081 * y^2) ) mod p
        BigInteger ySq = theY.multiply(theY).mod(p);
        BigInteger subRadicand1 = BigInteger.ONE.subtract(ySq);
        BigInteger subRadicand2 = BigInteger.ONE.add(d.negate().multiply(ySq));
        BigInteger radicand = subRadicand1.multiply(subRadicand2.modInverse(p)).mod(p);

        x = Objects.requireNonNull(sqrt(radicand, p, leastSignificantBitX)).mod(p);
    }

    /**
     * Constructs edwards curve point (0, 1) which is the neutral element.
     */
    public EllipticCurvePoint() {
        this(BigInteger.ZERO, BigInteger.ONE);
    }

    /**
     * Performs an elliptic curve (edwards curve) addition between this point and another point.
     * This is uses the Edwards point addition formula.
     * @param other the other point
     * @return the sum of two points
     */
    public EllipticCurvePoint add(final EllipticCurvePoint other) {
        // shared constant for denominator: d * x1 * d2 * y1 * y2
        BigInteger denom = d.multiply(x).multiply(other.x).multiply(y).multiply(other.y);

        // N_x = x1 * y2 + y1 * x2
        BigInteger sumXnumer = x.multiply(other.y).add(y.multiply(other.x));
        // N_y = y1 * y2 − x1 * x2
        BigInteger sumYnumer = y.multiply(other.y).subtract(x.multiply(other.x));

        // D_x = 1 + denom
        BigInteger sumXdenom = BigInteger.ONE.add(denom);
        // D_y = 1 - denom
        BigInteger sumYdenom = BigInteger.ONE.subtract(denom);

        return new EllipticCurvePoint(sumXnumer.multiply(sumXdenom.modInverse(p)).mod(p),
                                      sumYnumer.multiply(sumYdenom.modInverse(p)).mod(p));
    }

    /**
     * Gets the opposite point of this instance's point. Definition: the opposite a point (x, y) is (-x, y).
     * @return the opposite point
     */
    public EllipticCurvePoint getOppositePoint() {
        return new EllipticCurvePoint(x.multiply(BigInteger.valueOf(-1)), y);
    }

    /**
     * Exponentiation algorithm for points in an elliptic curve. This method multiplies itself with a scalar.
     * Algorithm is written by converting the python code from the professor's slide.
     * @param scalar the scalar
     * @return this current instance point multiplied by a scalar
     */
    public EllipticCurvePoint multiplyByScalar (final BigInteger scalar) {
        if (scalar.equals(BigInteger.ZERO)) {
            return new EllipticCurvePoint(); // neutral element
        }
        // s = (s_k, s_k-1, ... s_1, s_0)_2, s_k = 1 and it gets ignored
        String s = scalar.toString(2); // as base 2 string
        // G (base) is "this" instance
        EllipticCurvePoint V = this;

        // string indices start from left to right
        for (int i = 1; i < s.length(); i++) {
            V = V.add(V); // 2V or V+V
            if (s.charAt(i) == '1') {
                V = V.add(this);
            }
        }
        return V; // V = s * G
    }

    /**
     * Compute a square root of v mod p with a specified least-significant bit if such a root exists.
     * Code is taken from the project specification paper.
     * @param v   the radicand
     * @param p   the modulus (must satisfy p mod 4 = 3)
     * @param lsb desired least significant bit (true: 1, false: 0)
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     *         if such a root exists, otherwise null
     */
    private static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * The special point G which is called the public generator.
     * G is defined as a point (x_0, y_0)
     * where y_0 = -3 (mod p)
     * and   x_0 = certain unique even number
     * @return G (public generator)
     */
    public static EllipticCurvePoint getPublicGenerator() {
        // if x is even, then the least sig bit must be 0
        return new EllipticCurvePoint(BigInteger.valueOf(-3).mod(p), false);
    }

    /**
     * Tests if another elliptic curve point is the equal to this one by comparing x and y values.
     * @param obj the object to test for equality
     * @return true or false for equality
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof EllipticCurvePoint other) {
            return x.equals(other.x) && y.equals(other.y);
        }
        return false;
    }

    /**
     * Returns the x and y values of this Elliptic Curve Point.
     * @return the x and y coordinates separated by a new line
     */
    @Override
    public String toString() {
        return x + "\n" + y;
    }

    /**
     * Getter of the x value.
     * @return the x value of this point
     */
    public BigInteger getX() {
        return x;
    }

    /*
     * For testing only.
     * All testcases should output true
     */
//    public static void main(String[] args) {
//        // G = public generator with y = -3 (mod p)
//        BigInteger y = BigInteger.valueOf(-3).mod(p);
//        EllipticCurvePoint G = new EllipticCurvePoint(y, false);
//        EllipticCurvePoint O = new EllipticCurvePoint(); // neutral element
//
//        /* Test 1:
//         * 0 * G = O (neutral element)
//         */
//        System.out.println(G.multiplyByScalar(BigInteger.ZERO).equals(O));
//
//        /* Test 1:
//         * 1 * G = G
//         */
//        System.out.println(G.multiplyByScalar(BigInteger.ONE).equals(G));
//
//        /* Test 3:
//         * G + (-G) = O where -G = (p - x, y)
//         */
//        EllipticCurvePoint G2 = new EllipticCurvePoint(p.subtract(G.getX()), y);
//        System.out.println(G.add(G2).equals(O));
//
//        /* Test 4:
//         * 2 * G = G + G
//         */
//        System.out.println(G.multiplyByScalar(BigInteger.TWO).equals(G.add(G)));
//
//        /* Test 5:
//         * 4 * G = 2 * (2 * G)
//         */
//        System.out.println(G.multiplyByScalar(BigInteger.valueOf(4)).equals(
//                           G.multiplyByScalar(BigInteger.TWO).multiplyByScalar(BigInteger.TWO)));
//
//        /* Test 6:
//         * 4 * G =/= O
//         */
//        System.out.println(!(G.multiplyByScalar(BigInteger.TWO).equals(O)));
//
//        /* Test 7:
//         * r * G = O
//         */
//        System.out.println(G.multiplyByScalar(EllipticCurve.r).equals(O));
//        System.out.println("Repeated testing:");
//
//        // random number testing
//        for (int i = 0; i < 1; i++) {
//            BigInteger k = EllipticCurve.r.add(BigInteger.valueOf((int) (Math.random() * 10000000) + 10000000));
//            BigInteger l = EllipticCurve.r.add(BigInteger.valueOf((int) (Math.random() * 10000000) + 10000000));
//            BigInteger m = EllipticCurve.r.add(BigInteger.valueOf((int) (Math.random() * 10000000) + 10000000));
//
//            /* Test 8:
//             * k * G = (k mod r) * G
//             */
//            System.out.println(G.multiplyByScalar(k).equals(G.multiplyByScalar(k.mod(EllipticCurve.r))));
//
//            /* Test 9:
//             * (k + 1) * G = (k * G) + G
//             */
//            System.out.println(G.multiplyByScalar(k.add(BigInteger.ONE)).equals(
//                    G.multiplyByScalar(k).add(G)));
//
//            /* Test 10:
//             * (k + l) * G = (k * G) + (l * G)
//             */
//            System.out.println(G.multiplyByScalar(k.add(l)).equals(
//                    G.multiplyByScalar(k).add(G.multiplyByScalar(l))));
//
//            /* Test 11:
//             * k * (l * G) = l * (k * G) = (k * l mod r) * G
//             */
//            System.out.println(G.multiplyByScalar(l).multiplyByScalar(k).equals(
//                    G.multiplyByScalar(k).multiplyByScalar(l)));
//            System.out.println(G.multiplyByScalar(k).multiplyByScalar(l).equals(
//                    G.multiplyByScalar(k.multiply(l).mod(EllipticCurve.r))));
//
//            /* Test 12:
//             * (k * G) + ((l * G) + (m * G)) = ((k * G) + (l * G)) + (m * G)
//             */
//            System.out.println(G.multiplyByScalar(k).add(G.multiplyByScalar(l).add(G.multiplyByScalar(m))).equals(
//                    G.multiplyByScalar(m).add(G.multiplyByScalar(l).add(G.multiplyByScalar(k)))));
//        }
//    }
}
