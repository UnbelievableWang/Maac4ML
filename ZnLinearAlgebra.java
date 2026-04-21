package maac4ml;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * Small linear-algebra helper over Z_N plus a few group-vector helpers.
 * This is the "matrix operation version" used by the later MABIPFE demo.
 */
public final class ZnLinearAlgebra {
    private ZnLinearAlgebra() {
    }

    public static int[] randomSigned8Vector(int dim, Random random) {
        int[] out = new int[dim];
        for (int i = 0; i < dim; i++) {
            out[i] = random.nextInt(256) - 128;
        }
        return out;
    }

    public static int[] clampToSigned8(int[] values) {
        int[] out = new int[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = Math.max(-128, Math.min(127, values[i]));
        }
        return out;
    }

    public static BigInteger[] encodeSignedVector(int[] input, BigInteger modulus) {
        BigInteger[] out = new BigInteger[input.length];
        for (int i = 0; i < input.length; i++) {
            out[i] = encodeSignedInt(input[i], modulus);
        }
        return out;
    }

    public static BigInteger encodeSignedInt(int value, BigInteger modulus) {
        BigInteger v = BigInteger.valueOf(value);
        v = v.mod(modulus);
        return v.signum() < 0 ? v.add(modulus) : v;
    }

    public static BigInteger[] randomZnVector(int dim, CompositeOrderPP pp) {
        BigInteger[] out = new BigInteger[dim];
        for (int i = 0; i < dim; i++) {
            out[i] = pp.randomZn();
        }
        return out;
    }

    public static BigInteger[][] randomZnMatrixWithFirstRow(int rows, int cols, BigInteger[] firstRow,
                                                             CompositeOrderPP pp) {
        if (firstRow.length != cols) {
            throw new IllegalArgumentException("first row has wrong length");
        }
        BigInteger[][] out = new BigInteger[rows][cols];
        out[0] = Arrays.copyOf(firstRow, cols);
        for (int i = 1; i < rows; i++) {
            out[i] = randomZnVector(cols, pp);
        }
        return out;
    }

    public static BigInteger[] negate(BigInteger[] vector, BigInteger modulus) {
        BigInteger[] out = new BigInteger[vector.length];
        for (int i = 0; i < vector.length; i++) {
            out[i] = vector[i].negate().mod(modulus);
        }
        return out;
    }

    public static BigInteger dot(BigInteger[] left, BigInteger[] right, BigInteger modulus) {
        if (left.length != right.length) {
            throw new IllegalArgumentException("dot-product dimension mismatch");
        }
        BigInteger acc = BigInteger.ZERO;
        for (int i = 0; i < left.length; i++) {
            acc = acc.add(left[i].multiply(right[i]));
        }
        return acc.mod(modulus);
    }

    public static int dotSigned(int[] left, int[] right) {
        if (left.length != right.length) {
            throw new IllegalArgumentException("dot-product dimension mismatch");
        }
        int acc = 0;
        for (int i = 0; i < left.length; i++) {
            acc += left[i] * right[i];
        }
        return acc;
    }

    public static BigInteger[] rowVectorTimesMatrix(BigInteger[] row, BigInteger[][] matrix, BigInteger modulus) {
        int rows = matrix.length;
        int cols = matrix[0].length;
        if (row.length != rows) {
            throw new IllegalArgumentException("row/matrix dimension mismatch");
        }
        BigInteger[] out = new BigInteger[cols];
        Arrays.fill(out, BigInteger.ZERO);
        for (int j = 0; j < cols; j++) {
            BigInteger acc = BigInteger.ZERO;
            for (int i = 0; i < rows; i++) {
                acc = acc.add(row[i].multiply(matrix[i][j]));
            }
            out[j] = acc.mod(modulus);
        }
        return out;
    }

    public static int[] matVecInt(int[][] matrix, int[] vector) {
        int rows = matrix.length;
        int cols = matrix[0].length;
        if (vector.length != cols) {
            throw new IllegalArgumentException("matrix/vector dimension mismatch");
        }
        int[] out = new int[rows];
        for (int i = 0; i < rows; i++) {
            int acc = 0;
            for (int j = 0; j < cols; j++) {
                acc += matrix[i][j] * vector[j];
            }
            out[i] = acc;
        }
        return out;
    }

    public static Element multiExponentiateG(Element[] bases, BigInteger[] exponents, CompositeOrderPP pp) {
        if (bases.length != exponents.length) {
            throw new IllegalArgumentException("base/exponent dimension mismatch");
        }
        Element acc = pp.oneG().duplicate();
        for (int i = 0; i < bases.length; i++) {
            BigInteger exp = exponents[i];
            Element term = bases[i].duplicate().pow(exp.abs());
            if (exp.signum() < 0) {
                term = term.invert();
            }
            acc = acc.mul(term);
        }
        return acc.getImmutable();
    }

    public static Element multiExponentiateGT(Element[] bases, BigInteger[] exponents, CompositeOrderPP pp) {
        if (bases.length != exponents.length) {
            throw new IllegalArgumentException("base/exponent dimension mismatch");
        }
        Element acc = pp.oneGT().duplicate();
        for (int i = 0; i < bases.length; i++) {
            BigInteger exp = exponents[i];
            Element term = bases[i].duplicate().pow(exp.abs());
            if (exp.signum() < 0) {
                term = term.invert();
            }
            acc = acc.mul(term);
        }
        return acc.getImmutable();
    }

    public static int bruteForceBoundForSigned8(int dimension) {
        return dimension * 127 * 127;
    }

    public static long sizeOfBigIntegerMatrix(BigInteger[][] matrix) {
        long total = 0L;
        for (BigInteger[] row : matrix) {
            total += CompositeOrderPP.sizeOfBigIntegerArray(row);
        }
        return total;
    }

    public static String vectorToString(int[] vector) {
        return Arrays.toString(vector);
    }
}
