package maac4ml;

import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Demo-oriented implementation of the user's MABIPFE construction.
 *
 * Notes:
 * - This follows the paper-level algebra closely enough for benchmarking and
 *   integration into the Maac4ML prototype.
 * - The access policy used in the demo is an AND-style LSSS matrix with a
 *   trivial reconstruction vector (all ones), which avoids modular inversion
 *   in the composite-order setting.
 * - Inner-product recovery uses brute-force enumeration as requested.
 */
public class MABIPFE {
    private final CompositeOrderPP pp;
    private final int dimension;

    public MABIPFE(CompositeOrderPP pp, int dimension) {
        this.pp = pp;
        this.dimension = dimension;
    }

    public CompositeOrderPP getPp() {
        return pp;
    }

    public int getDimension() {
        return dimension;
    }

    public AuthorityKeyPair aaSetup(int attributeId) {
        BigInteger[] a = ZnLinearAlgebra.randomZnVector(dimension, pp);
        BigInteger[] b = ZnLinearAlgebra.randomZnVector(dimension, pp);
        Element[] pkA = new Element[dimension];
        Element[] pkB = new Element[dimension];
        for (int j = 0; j < dimension; j++) {
            pkA[j] = pp.gPow(a[j]);
            pkB[j] = pp.gPow(b[j]);
        }
        return new AuthorityKeyPair(attributeId, a, b, pkA, pkB);
    }

    public UserKeyPart kGen(String rid, AuthorityKeyPair authority, BigInteger[] uEncoded) {
        Element hRu = pp.hashToGroup(rid, uEncoded);
        Element hRuTimesH = hRu.duplicate().mul(pp.getHBase()).getImmutable();
        BigInteger expA = ZnLinearAlgebra.dot(authority.aVector, uEncoded, pp.getOrder());
        BigInteger expB = ZnLinearAlgebra.dot(authority.bVector, uEncoded, pp.getOrder());
        Element krA = hRuTimesH.pow(expA).getImmutable();
        Element krB = hRu.duplicate().pow(expB).getImmutable();
        return new UserKeyPart(authority.attributeId, krA, krB);
    }

    public Ciphertext enc(Map<Integer, AuthorityKeyPair> authorities, AccessPolicy policy, BigInteger[] vEncoded) {
        int n = policy.nCols;
        int ell = policy.gamma.length;

        BigInteger[] z = ZnLinearAlgebra.randomZnVector(dimension, pp);
        BigInteger[][] vA = ZnLinearAlgebra.randomZnMatrixWithFirstRow(n, dimension, z, pp);
        BigInteger[][] vB = ZnLinearAlgebra.randomZnMatrixWithFirstRow(n, dimension,
                ZnLinearAlgebra.negate(z, pp.getOrder()), pp);

        Element[] c0 = new Element[dimension];
        for (int j = 0; j < dimension; j++) {
            Element mask = pp.pairing(pp.getGBase(), pp.getHBase()).pow(z[j]).getImmutable();
            Element msg = pp.getGtBase().duplicate().pow(vEncoded[j]).getImmutable();
            c0[j] = mask.duplicate().mul(msg).getImmutable();
        }

        Element[] c1A = new Element[ell];
        Element[] c1B = new Element[ell];
        Element[][] c2A = new Element[ell][dimension];
        Element[][] c2B = new Element[ell][dimension];

        for (int x = 0; x < ell; x++) {
            int attributeId = policy.rho[x];
            AuthorityKeyPair authority = authorities.get(attributeId);
            if (authority == null) {
                throw new IllegalArgumentException("missing authority for attribute " + attributeId);
            }
            BigInteger rA = pp.randomZn();
            BigInteger rB = pp.randomZn();
            c1A[x] = pp.gPow(rA);
            c1B[x] = pp.gPow(rB);

            BigInteger[] sigmaA = ZnLinearAlgebra.rowVectorTimesMatrix(policy.gamma[x], vA, pp.getOrder());
            BigInteger[] sigmaB = ZnLinearAlgebra.rowVectorTimesMatrix(policy.gamma[x], vB, pp.getOrder());

            for (int j = 0; j < dimension; j++) {
                Element leftA = authority.pkA[j].duplicate().pow(rA).getImmutable();
                Element rightA = pp.gPow(sigmaA[j]);
                c2A[x][j] = leftA.duplicate().mul(rightA).getImmutable();

                Element leftB = authority.pkB[j].duplicate().pow(rB).getImmutable();
                Element rightB = pp.gPow(sigmaB[j]);
                c2B[x][j] = leftB.duplicate().mul(rightB).getImmutable();
            }
        }

        return new Ciphertext(policy, c0, c1A, c1B, c2A, c2B, z, vEncoded);
    }

    public DecryptionResult dec(String rid,
            Map<Integer, UserKeyPart> userKeyParts,
            Ciphertext ciphertext,
            BigInteger[] uEncoded,
            int bruteForceBound) {
List<Integer> authorizedRows = ciphertext.policy.authorizedRows(userKeyParts.keySet());
if (authorizedRows.isEmpty()) {
return DecryptionResult.rejected("policy not satisfied");
}

long t0 = System.nanoTime();

Element hRu = pp.hashToGroup(rid, uEncoded);
Element hRuTimesH = hRu.duplicate().mul(pp.getHBase()).getImmutable();
Element d = pp.oneGT().duplicate();

for (int rowIndex : authorizedRows) {
int attributeId = ciphertext.policy.rho[rowIndex];
UserKeyPart part = userKeyParts.get(attributeId);

Element c2Au = ZnLinearAlgebra.multiExponentiateG(ciphertext.c2A[rowIndex], uEncoded, pp);
Element c2Bu = ZnLinearAlgebra.multiExponentiateG(ciphertext.c2B[rowIndex], uEncoded, pp);

Element dA = pp.pairing(c2Au, hRuTimesH)
.duplicate()
.mul(pp.pairing(ciphertext.c1A[rowIndex].duplicate().invert(), part.krA))
.getImmutable();

Element dB = pp.pairing(c2Bu, hRu)
.duplicate()
.mul(pp.pairing(ciphertext.c1B[rowIndex].duplicate().invert(), part.krB))
.getImmutable();

d = d.mul(dA).mul(dB);
}

Element c0u = ZnLinearAlgebra.multiExponentiateGT(ciphertext.c0, uEncoded, pp);
Element recoveredGt = c0u.duplicate().mul(d.duplicate().invert()).getImmutable();

long t1 = System.nanoTime();

Integer innerProduct = bruteForceDiscreteLog(recoveredGt, bruteForceBound);

long t2 = System.nanoTime();

double decCoreMs = (t1 - t0) / 1_000_000.0;
double dlogMs = (t2 - t1) / 1_000_000.0;
double decTotalMs = (t2 - t0) / 1_000_000.0;

System.out.printf(
"Dec breakdown: core=%.3f ms | dlog=%.3f ms | total=%.3f ms%n",
decCoreMs, dlogMs, decTotalMs
);

if (innerProduct == null) {
return DecryptionResult.failure(
"brute-force recovery failed within bound " + bruteForceBound,
recoveredGt
);
}

return DecryptionResult.success(
innerProduct,
recoveredGt,
bruteForceBound,
authorizedRows.size()
);
}

    public Integer bruteForceDiscreteLog(Element target, int bound) {
        for (int m = -bound; m <= bound; m++) {
            Element guess = pp.gtPow(BigInteger.valueOf(m));
            if (guess.isEqual(target)) {
                return m;
            }
        }
        return null;
    }

    public static final class AuthorityKeyPair {
        public final int attributeId;
        public final BigInteger[] aVector;
        public final BigInteger[] bVector;
        public final Element[] pkA;
        public final Element[] pkB;

        public AuthorityKeyPair(int attributeId,
                                BigInteger[] aVector,
                                BigInteger[] bVector,
                                Element[] pkA,
                                Element[] pkB) {
            this.attributeId = attributeId;
            this.aVector = Arrays.copyOf(aVector, aVector.length);
            this.bVector = Arrays.copyOf(bVector, bVector.length);
            this.pkA = pkA.clone();
            this.pkB = pkB.clone();
        }

        public long publicKeyBytes() {
            return CompositeOrderPP.sizeOfElementArray(pkA) + CompositeOrderPP.sizeOfElementArray(pkB);
        }

        public long secretKeyBytes() {
            return CompositeOrderPP.sizeOfBigIntegerArray(aVector) + CompositeOrderPP.sizeOfBigIntegerArray(bVector);
        }
    }

    public static final class UserKeyPart {
        public final int attributeId;
        public final Element krA;
        public final Element krB;

        public UserKeyPart(int attributeId, Element krA, Element krB) {
            this.attributeId = attributeId;
            this.krA = krA;
            this.krB = krB;
        }

        public long bytes() {
            return CompositeOrderPP.sizeOfElement(krA) + CompositeOrderPP.sizeOfElement(krB);
        }
    }

    public static final class AccessPolicy {
        public final BigInteger[][] gamma;
        public final int[] rho;
        public final int nCols;
        private final int[] requiredAttributes;

        private AccessPolicy(BigInteger[][] gamma, int[] rho, int[] requiredAttributes) {
            this.gamma = gamma;
            this.rho = rho;
            this.requiredAttributes = requiredAttributes;
            this.nCols = gamma[0].length;
        }

        /**
         * Standard AND-style LSSS with all-one reconstruction coefficients:
         * r1=(1,1,0,...,0), r2=(0,-1,1,0,...), ..., rn=(0,...,0,-1).
         * Summing all rows yields e1, so all listed attributes are required.
         */
        public static AccessPolicy andPolicy(int[] attributeIds, CompositeOrderPP pp) {
            int n = attributeIds.length;
            if (n == 0) {
                throw new IllegalArgumentException("policy must contain at least one attribute");
            }
            BigInteger[][] gamma = new BigInteger[n][n];
            for (BigInteger[] row : gamma) {
                Arrays.fill(row, BigInteger.ZERO);
            }
            BigInteger one = BigInteger.ONE.mod(pp.getOrder());
            BigInteger minusOne = BigInteger.ONE.negate().mod(pp.getOrder());
            if (n == 1) {
                gamma[0][0] = one;
            } else {
                gamma[0][0] = one;
                gamma[0][1] = one;
                for (int i = 1; i < n - 1; i++) {
                    gamma[i][i] = minusOne;
                    gamma[i][i + 1] = one;
                }
                gamma[n - 1][n - 1] = minusOne;
            }
            return new AccessPolicy(gamma, Arrays.copyOf(attributeIds, attributeIds.length),
                    Arrays.copyOf(attributeIds, attributeIds.length));
        }

        public boolean isSatisfiedBy(Set<Integer> attributes) {
            for (int attr : requiredAttributes) {
                if (!attributes.contains(attr)) {
                    return false;
                }
            }
            return true;
        }

        public List<Integer> authorizedRows(Set<Integer> attributes) {
            if (!isSatisfiedBy(attributes)) {
                return new ArrayList<>();
            }
            List<Integer> rows = new ArrayList<>();
            for (int i = 0; i < rho.length; i++) {
                if (attributes.contains(rho[i])) {
                    rows.add(i);
                }
            }
            return rows;
        }

        public long bytes() {
            return ZnLinearAlgebra.sizeOfBigIntegerMatrix(gamma) + CompositeOrderPP.sizeOfIntArray(rho);
        }
    }

    public static final class Ciphertext {
        public final AccessPolicy policy;
        public final Element[] c0;
        public final Element[] c1A;
        public final Element[] c1B;
        public final Element[][] c2A;
        public final Element[][] c2B;
        public final BigInteger[] zForDebug;
        public final BigInteger[] vForDebug;

        public Ciphertext(AccessPolicy policy,
                          Element[] c0,
                          Element[] c1A,
                          Element[] c1B,
                          Element[][] c2A,
                          Element[][] c2B,
                          BigInteger[] zForDebug,
                          BigInteger[] vForDebug) {
            this.policy = policy;
            this.c0 = c0.clone();
            this.c1A = c1A.clone();
            this.c1B = c1B.clone();
            this.c2A = c2A.clone();
            this.c2B = c2B.clone();
            this.zForDebug = Arrays.copyOf(zForDebug, zForDebug.length);
            this.vForDebug = Arrays.copyOf(vForDebug, vForDebug.length);
        }

        public long bytes() {
            return policy.bytes()
                    + CompositeOrderPP.sizeOfElementArray(c0)
                    + CompositeOrderPP.sizeOfElementArray(c1A)
                    + CompositeOrderPP.sizeOfElementArray(c1B)
                    + CompositeOrderPP.sizeOfElementMatrix(c2A)
                    + CompositeOrderPP.sizeOfElementMatrix(c2B);
        }
    }

    public static final class DecryptionResult {
        public final boolean success;
        public final boolean policySatisfied;
        public final String message;
        public final Integer innerProduct;
        public final Element recoveredTarget;
        public final int bruteForceBound;
        public final int usedRows;

        private DecryptionResult(boolean success,
                                 boolean policySatisfied,
                                 String message,
                                 Integer innerProduct,
                                 Element recoveredTarget,
                                 int bruteForceBound,
                                 int usedRows) {
            this.success = success;
            this.policySatisfied = policySatisfied;
            this.message = message;
            this.innerProduct = innerProduct;
            this.recoveredTarget = recoveredTarget;
            this.bruteForceBound = bruteForceBound;
            this.usedRows = usedRows;
        }

        public static DecryptionResult success(int innerProduct, Element recoveredTarget, int bound, int usedRows) {
            return new DecryptionResult(true, true, "ok", innerProduct, recoveredTarget, bound, usedRows);
        }

        public static DecryptionResult rejected(String message) {
            return new DecryptionResult(false, false, message, null, null, 0, 0);
        }

        public static DecryptionResult failure(String message, Element recoveredTarget) {
            return new DecryptionResult(false, true, message, null, recoveredTarget, 0, 0);
        }
    }

    public static final class MetricsReport {
        private final Map<String, Double> timesMs = new LinkedHashMap<>();
        private final Map<String, Long> sizesBytes = new LinkedHashMap<>();
        private final Map<String, String> notes = new LinkedHashMap<>();

        public void putTime(String key, double valueMs) {
            timesMs.put(key, valueMs);
        }

        public void putSize(String key, long bytes) {
            sizesBytes.put(key, bytes);
        }

        public void putNote(String key, String value) {
            notes.put(key, value);
        }

        public double getTime(String key) {
            return timesMs.getOrDefault(key, 0.0);
        }

        public long getSize(String key) {
            return sizesBytes.getOrDefault(key, 0L);
        }

        public String getNote(String key) {
            return notes.get(key);
        }

        public void print(String title) {
            System.out.println("\n================ " + title + " ================");
            for (Map.Entry<String, Double> e : timesMs.entrySet()) {
                System.out.printf("%-35s : %12.3f ms%n", e.getKey(), e.getValue());
            }
            for (Map.Entry<String, Long> e : sizesBytes.entrySet()) {
                System.out.printf("%-35s : %12d bytes%n", e.getKey(), e.getValue());
            }
            for (Map.Entry<String, String> e : notes.entrySet()) {
                System.out.printf("%-35s : %s%n", e.getKey(), e.getValue());
            }
        }
    }
}
