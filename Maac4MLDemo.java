package maac4ml;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;

/**
 * End-to-end Maac4ML demo built on top of the demo MABIPFE implementation.
 *
 * Goals:
 * 1) keep the algebra close to the paper;
 * 2) keep all pivotal vectors within signed 8-bit range;
 * 3) recover the inner product by brute-force enumeration;
 * 4) expose system-level metrics that reviewers usually ask about.
 */
public class Maac4MLDemo {
    private static final Random RANDOM = new Random(20260421L);

    public static void main(String[] args) {
        DemoConfig config = DemoConfig.defaultConfig();
        DemoOutputs outputs = runSingleDemo(config, true);
        outputs.metrics.print("Maac4ML single-demo metrics");

        System.out.println("\nRecovered inner product = " + outputs.recoveredInnerProduct);
        System.out.println("Plaintext inner product = " + outputs.plainInnerProduct);
        System.out.println("Authorized decryption ok = " + outputs.authorizedOk);
        System.out.println("Unauthorized decryption rejected = " + outputs.unauthorizedRejected);

        runRepeatedQueries(config, 5);
        runAuthorityScaling(new int[]{1, 2, 4, 6});
    }

    public static DemoOutputs runSingleDemo(DemoConfig config, boolean verbose) {
        long t0 = System.nanoTime();
        CompositeOrderPP pp = new CompositeOrderPP();
        long t1 = System.nanoTime();
        MABIPFE scheme = new MABIPFE(pp, config.pivotalDim);

        MABIPFE.MetricsReport metrics = new MABIPFE.MetricsReport();
        metrics.putTime("PP generation", elapsedMs(t0, t1));
        metrics.putNote("vector dimension s", String.valueOf(config.pivotalDim));
        metrics.putNote("8-bit bound per coordinate", "[-128, 127]");
        metrics.putSize("|G|", CompositeOrderPP.sizeOfElement(pp.getGBase()));
        metrics.putSize("|GT|", CompositeOrderPP.sizeOfElement(pp.getGtBase()));

        int[] attributeIds = new int[config.authorityCount];
        for (int i = 0; i < config.authorityCount; i++) {
            attributeIds[i] = i + 1;
        }
        MABIPFE.AccessPolicy policy = MABIPFE.AccessPolicy.andPolicy(attributeIds, pp);

        Map<Integer, MABIPFE.AuthorityKeyPair> authorities = new LinkedHashMap<>();
        double aaSetupTotalMs = 0.0;
        long pkBytes = 0L;
        long skBytes = 0L;
        for (int attrId : attributeIds) {
            long s0 = System.nanoTime();
            MABIPFE.AuthorityKeyPair kp = scheme.aaSetup(attrId);
            long s1 = System.nanoTime();
            aaSetupTotalMs += elapsedMs(s0, s1);
            pkBytes += kp.publicKeyBytes();
            skBytes += kp.secretKeyBytes();
            authorities.put(attrId, kp);
        }
        metrics.putTime("AASetup total", aaSetupTotalMs);
        metrics.putTime("AASetup avg/authority", aaSetupTotalMs / Math.max(1, config.authorityCount));
        metrics.putSize("total authority PK bytes", pkBytes);
        metrics.putSize("total authority SK bytes", skBytes);
        metrics.putSize("policy bytes", policy.bytes());

        ToyModel model = ToyModel.randomModel(config.inputDim, config.pivotalDim, config.outputDim, RANDOM);
        int[] input = ZnLinearAlgebra.randomSigned8Vector(config.inputDim, RANDOM);
        int[] yPlain = model.f1(input);
        BigInteger[] yEncoded = ZnLinearAlgebra.encodeSignedVector(yPlain, pp.getOrder());
        BigInteger[] wpEncoded = ZnLinearAlgebra.encodeSignedVector(model.wp, pp.getOrder());
        int bruteForceBound = ZnLinearAlgebra.bruteForceBoundForSigned8(config.pivotalDim);
        metrics.putNote("enumeration bound", String.valueOf(bruteForceBound));
        metrics.putNote("policy type", "AND over all " + config.authorityCount + " attributes");

        long p0 = System.nanoTime();
        MABIPFE.Ciphertext ciphertext = scheme.enc(authorities, policy, wpEncoded);
        long p1 = System.nanoTime();
        metrics.putTime("Model publishing / Enc", elapsedMs(p0, p1));
        metrics.putSize("ciphertext bytes", ciphertext.bytes());
        metrics.putSize("published model bytes (est.)", ciphertext.bytes() + model.publicModelBytes());

        int[] publicOutputPlain = model.f2(relu(ZnLinearAlgebra.dotSigned(yPlain, model.wp)));
        metrics.putNote("published model public part", "(F1, W1, F2, W2\\setminus{wp}, fp, CT)");

        long online0 = System.nanoTime();
        long f10 = System.nanoTime();
        int[] yOnline = model.f1(input);
        long f11 = System.nanoTime();
        BigInteger[] yOnlineEncoded = ZnLinearAlgebra.encodeSignedVector(yOnline, pp.getOrder());

        long requestBytes = CompositeOrderPP.sizeOfString(config.userRid)
                + CompositeOrderPP.sizeOfBigIntegerArray(yOnlineEncoded);
        metrics.putSize("single authority request bytes", requestBytes);
        metrics.putSize("total request bytes", requestBytes * config.authorityCount);

        Map<Integer, MABIPFE.UserKeyPart> userKeys = new LinkedHashMap<>();
        double kgenTotalMs = 0.0;
        double kgenMaxMs = 0.0;
        long responseBytes = 0L;
        for (int attrId : attributeIds) {
            long k0 = System.nanoTime();
            MABIPFE.UserKeyPart keyPart = scheme.kGen(config.userRid, authorities.get(attrId), yOnlineEncoded);
            long k1 = System.nanoTime();
            double used = elapsedMs(k0, k1);
            kgenTotalMs += used;
            kgenMaxMs = Math.max(kgenMaxMs, used);
            responseBytes += keyPart.bytes();
            userKeys.put(attrId, keyPart);
        }
        long d0 = System.nanoTime();
        MABIPFE.DecryptionResult dec = scheme.dec(config.userRid, userKeys, ciphertext, yOnlineEncoded, bruteForceBound);
        long d1 = System.nanoTime();

        if (!dec.success) {
            throw new IllegalStateException("authorized decryption failed: " + dec.message);
        }
        int xp1 = relu(dec.innerProduct);
        long f20 = System.nanoTime();
        int[] modelOutput = model.f2(xp1);
        long f21 = System.nanoTime();
        long online1 = System.nanoTime();

        int plainInner = ZnLinearAlgebra.dotSigned(yOnline, model.wp);
        boolean authorizedOk = plainInner == dec.innerProduct;

        metrics.putTime("F1 time", elapsedMs(f10, f11));
        metrics.putTime("KGen total", kgenTotalMs);
        metrics.putTime("KGen avg/authority", kgenTotalMs / Math.max(1, config.authorityCount));
        metrics.putTime("KGen max/authority", kgenMaxMs);
        metrics.putTime("Dec time", elapsedMs(d0, d1));
        metrics.putTime("F2 time", elapsedMs(f20, f21));
        metrics.putTime("Online end-to-end", elapsedMs(online0, online1));
        metrics.putSize("single authority response bytes", responseBytes / Math.max(1, config.authorityCount));
        metrics.putSize("total response bytes", responseBytes);
        metrics.putNote("plaintext pivotal input y_p", Arrays.toString(yOnline));
        metrics.putNote("plaintext pivotal weight w_p", Arrays.toString(model.wp));
        metrics.putNote("authorized output", Arrays.toString(modelOutput));
        metrics.putNote("plain output", Arrays.toString(publicOutputPlain));

        Map<Integer, MABIPFE.UserKeyPart> unauthorizedKeys = new LinkedHashMap<>(userKeys);
        unauthorizedKeys.remove(attributeIds[attributeIds.length - 1]);
        MABIPFE.DecryptionResult unauthorized = scheme.dec(config.userRid, unauthorizedKeys, ciphertext,
                yOnlineEncoded, bruteForceBound);
        boolean unauthorizedRejected = !unauthorized.policySatisfied;

        if (verbose) {
            System.out.println("\nInput x               = " + Arrays.toString(input));
            System.out.println("Pivotal input y_p     = " + Arrays.toString(yOnline));
            System.out.println("Pivotal weight w_p    = " + Arrays.toString(model.wp));
            System.out.println("Plain dot(y_p, w_p)   = " + plainInner);
            System.out.println("Recovered dot(y_p,w_p)= " + dec.innerProduct);
            System.out.println("Final output          = " + Arrays.toString(modelOutput));
        }

        return new DemoOutputs(metrics, plainInner, dec.innerProduct, authorizedOk, unauthorizedRejected);
    }

    public static void runRepeatedQueries(DemoConfig config, int queries) {
        double total = 0.0;
        for (int i = 0; i < queries; i++) {
            DemoOutputs outputs = runSingleDemo(config, false);
            total += outputs.metricsValue("Online end-to-end");
        }
        System.out.printf("\nAverage online latency over %d fresh runs: %.3f ms%n", queries, total / queries);
    }

    public static void runAuthorityScaling(int[] authorityCounts) {
        System.out.println("\n==== Authority scaling ====");
        for (int authorityCount : authorityCounts) {
            DemoConfig cfg = new DemoConfig(6, 6, 3, authorityCount, "user-demo-01");
            DemoOutputs outputs = runSingleDemo(cfg, false);
            System.out.printf("authorities=%d | KGen total=%.3f ms | Dec=%.3f ms | Online=%.3f ms | CT=%d bytes%n",
                    authorityCount,
                    outputs.metricsValue("KGen total"),
                    outputs.metricsValue("Dec time"),
                    outputs.metricsValue("Online end-to-end"),
                    outputs.metricSize("ciphertext bytes"));
        }
    }

    private static int relu(int x) {
        return Math.max(0, x);
    }

    private static double elapsedMs(long start, long end) {
        return (end - start) / 1_000_000.0;
    }

    public static final class DemoConfig {
        public final int inputDim;
        public final int pivotalDim;
        public final int outputDim;
        public final int authorityCount;
        public final String userRid;

        public DemoConfig(int inputDim, int pivotalDim, int outputDim, int authorityCount, String userRid) {
            this.inputDim = inputDim;
            this.pivotalDim = pivotalDim;
            this.outputDim = outputDim;
            this.authorityCount = authorityCount;
            this.userRid = userRid;
        }

        public static DemoConfig defaultConfig() {
            return new DemoConfig(6, 6, 3, 4, "user-demo-01");
        }
    }

    public static final class ToyModel {
        private final int[][] w1;
        private final int[] wp;
        private final int[][] w2;
        private final int[] b2;

        public ToyModel(int[][] w1, int[] wp, int[][] w2, int[] b2) {
            this.w1 = w1;
            this.wp = wp;
            this.w2 = w2;
            this.b2 = b2;
        }

        public static ToyModel randomModel(int inputDim, int pivotalDim, int outputDim, Random random) {
            int[][] w1 = new int[pivotalDim][inputDim];
            for (int i = 0; i < pivotalDim; i++) {
                for (int j = 0; j < inputDim; j++) {
                    w1[i][j] = random.nextInt(11) - 5;
                }
            }
            int[] wp = ZnLinearAlgebra.randomSigned8Vector(pivotalDim, random);
            int[][] w2 = new int[outputDim][1];
            int[] b2 = new int[outputDim];
            for (int i = 0; i < outputDim; i++) {
                w2[i][0] = random.nextInt(11) - 5;
                b2[i] = random.nextInt(21) - 10;
            }
            return new ToyModel(w1, wp, w2, b2);
        }

        public int[] f1(int[] x) {
            return ZnLinearAlgebra.clampToSigned8(ZnLinearAlgebra.matVecInt(w1, x));
        }

        public int[] f2(int xp1) {
            int[] out = new int[w2.length];
            for (int i = 0; i < w2.length; i++) {
                out[i] = w2[i][0] * xp1 + b2[i];
            }
            return out;
        }

        public long publicModelBytes() {
            return (long) w1.length * w1[0].length * 4L
                    + (long) w2.length * 4L
                    + (long) b2.length * 4L;
        }
    }

    public static final class DemoOutputs {
        public final MABIPFE.MetricsReport metrics;
        public final int plainInnerProduct;
        public final int recoveredInnerProduct;
        public final boolean authorizedOk;
        public final boolean unauthorizedRejected;

        public DemoOutputs(MABIPFE.MetricsReport metrics,
                           int plainInnerProduct,
                           int recoveredInnerProduct,
                           boolean authorizedOk,
                           boolean unauthorizedRejected) {
            this.metrics = metrics;
            this.plainInnerProduct = plainInnerProduct;
            this.recoveredInnerProduct = recoveredInnerProduct;
            this.authorizedOk = authorizedOk;
            this.unauthorizedRejected = unauthorizedRejected;
        }

        public double metricsValue(String key) {
            return metrics.getTime(key);
        }

        public long metricSize(String key) {
            return metrics.getSize(key);
        }
    }
}
