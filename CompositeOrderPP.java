package maac4ml;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

/**
 * Composite-order public parameters for the demo prototype.
 *
 * This class is intentionally close in spirit to the user-provided skeleton,
 * but fixes two practical issues for the demo:
 * 1) the GT exponentiation base is derived from a real pairing value rather
 *    than the identity element;
 * 2) helper methods are added for signed exponentiation, hashing, and size
 *    accounting so the later benchmarks are easy to extend.
 */
public class CompositeOrderPP {
    private final Pairing pairing;
    private final Field gField;
    private final Field gtField;
    private final Field znField;

    private final Element gBase;
    private final Element hBase;
    private final Element gtBase;

    private final ElementPowPreProcessing gPow;
    private final ElementPowPreProcessing hPow;
    private final ElementPowPreProcessing gtPow;

    private final BigInteger order;
    private final Random random;

    public CompositeOrderPP() {
        this(3, 512 / 3, new Random(20260421L));
    }

    public CompositeOrderPP(int numPrimes, int qBits, Random random) {
        PairingParametersGenerator generator = new TypeA1CurveGenerator(numPrimes, qBits);
        PairingParameters parameters = generator.generate();

        this.pairing = PairingFactory.getPairing(parameters);
        this.gField = pairing.getG1();
        this.gtField = pairing.getGT();
        this.znField = pairing.getZr();
        this.order = znField.getOrder();
        this.random = random;

        this.gBase = gField.newRandomElement().getImmutable();
        this.hBase = gField.newRandomElement().getImmutable();
        this.gtBase = pairing.pairing(gBase, hBase).getImmutable();

        this.gPow = gBase.getElementPowPreProcessing();
        this.hPow = hBase.getElementPowPreProcessing();
        this.gtPow = gtBase.getElementPowPreProcessing();
    }

    public Pairing getPairing() {
        return pairing;
    }

    public Field getGField() {
        return gField;
    }

    public Field getGtField() {
        return gtField;
    }

    public Field getZnField() {
        return znField;
    }

    public BigInteger getOrder() {
        return order;
    }

    public Element getGBase() {
        return gBase.duplicate().getImmutable();
    }

    public Element getHBase() {
        return hBase.duplicate().getImmutable();
    }

    public Element getGtBase() {
        return gtBase.duplicate().getImmutable();
    }

    public BigInteger randomZn() {
        BigInteger sample;
        do {
            sample = new BigInteger(order.bitLength(), random).mod(order);
        } while (sample.signum() < 0 || sample.compareTo(order) >= 0);
        return sample;
    }

    public BigInteger randomZnNonZero() {
        BigInteger x;
        do {
            x = randomZn();
        } while (x.equals(BigInteger.ZERO));
        return x;
    }

    public Element gPow(BigInteger exponent) {
        return signedPow(gPow, gBase, exponent);
    }

    public Element hPow(BigInteger exponent) {
        return signedPow(hPow, hBase, exponent);
    }

    public Element gtPow(BigInteger exponent) {
        return signedPow(gtPow, gtBase, exponent);
    }

    public Element pairing(Element left, Element right) {
        return pairing.pairing(left, right).getImmutable();
    }

    public Element oneG() {
        return gField.newOneElement().getImmutable();
    }

    public Element oneGT() {
        return gtField.newOneElement().getImmutable();
    }

    public BigInteger normalize(BigInteger value) {
        BigInteger reduced = value.mod(order);
        return reduced.signum() < 0 ? reduced.add(order) : reduced;
    }

    public BigInteger encodeSignedInt(int value) {
        return normalize(BigInteger.valueOf(value));
    }

    public Element hashToGroup(String rid, BigInteger[] vector) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(rid.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) ':');
            for (BigInteger coordinate : vector) {
                byte[] bytes = coordinate.toByteArray();
                digest.update(bytes);
                digest.update((byte) ',');
            }
            BigInteger exponent = new BigInteger(1, digest.digest()).mod(order);
            return gPow(exponent);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public static long sizeOfElement(Element element) {
        return element.toBytes().length;
    }

    public static long sizeOfBigInteger(BigInteger value) {
        return value.toByteArray().length;
    }

    public static long sizeOfBigIntegerArray(BigInteger[] values) {
        long total = 0L;
        for (BigInteger value : values) {
            total += sizeOfBigInteger(value);
        }
        return total;
    }

    public static long sizeOfElementArray(Element[] values) {
        long total = 0L;
        for (Element value : values) {
            total += sizeOfElement(value);
        }
        return total;
    }

    public static long sizeOfElementMatrix(Element[][] values) {
        long total = 0L;
        for (Element[] row : values) {
            total += sizeOfElementArray(row);
        }
        return total;
    }

    public static long sizeOfIntArray(int[] values) {
        return 4L * values.length;
    }

    public static long sizeOfString(String s) {
        return s.getBytes(StandardCharsets.UTF_8).length;
    }

    private Element signedPow(ElementPowPreProcessing preProc, Element base, BigInteger exponent) {
        BigInteger e = exponent;
        if (e.signum() >= 0) {
            return preProc.pow(e).getImmutable();
        }
        return preProc.pow(e.negate()).invert().getImmutable();
    }

    @Override
    public String toString() {
        return "CompositeOrderPP{" +
                "|G|=" + sizeOfElement(gBase) +
                ", |GT|=" + sizeOfElement(gtBase) +
                ", |ZN|~=" + sizeOfBigInteger(order) +
                ", orderBits=" + order.bitLength() +
                '}';
    }

    public static void main(String[] args) {
        CompositeOrderPP pp = new CompositeOrderPP();
        System.out.println(pp);
        System.out.println("g base bytes = " + sizeOfElement(pp.getGBase()));
        System.out.println("gt base bytes = " + sizeOfElement(pp.getGtBase()));
        System.out.println("sample H(RID,u) bytes = " + sizeOfElement(pp.hashToGroup("demo", new BigInteger[]{BigInteger.ONE, BigInteger.TWO})));
        System.out.println("example normalize = " + Arrays.toString(new BigInteger[]{pp.normalize(BigInteger.valueOf(-3)), pp.normalize(BigInteger.valueOf(7))}));
    }
}
