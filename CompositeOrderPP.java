package my_test;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
//import it.unisa.dia.gas.plaf.jpbc.util.io.PairingParametersReader;
import java.util.HashMap;

public class CompositeOrderPP {
    ElementPowPreProcessing g1;
    ElementPowPreProcessing g2;
    ElementPowPreProcessing egg;

    Pairing bp;
    Field G1;
    Field G2;
    Field Gt;
    Field ZN;
    CompositeOrderPP() {
        // Load custom pairing parameters for composite order from a file or string.
    	 PairingParametersGenerator parametersGenerator = new TypeA1CurveGenerator(3, 512/3);
         PairingParameters pp = parametersGenerator.generate();

         this.bp = PairingFactory.getPairing(pp);
        this.G1 = bp.getG1();
        this.G2=bp.getG2();
        this.Gt=bp.getGT();
        Element gg1 = G1.newRandomElement();
        this.g1 = gg1.getElementPowPreProcessing();
        Element gg2 = G2.newRandomElement();
        this.g2 = gg2.getElementPowPreProcessing();
        Element ggg = Gt.newOneElement();
        this.ZN= bp.getZr();
        this.egg = ggg.getElementPowPreProcessing();
        
    }
    public Element g_(Element z) {
    	return g1.pow(z.toBigInteger());
		//return g1.pow(ZN.getNqr().toBigInteger());
	}
    public Element egg_(Element z) {
    	return egg.pow(z.toBigInteger());
		//return g1.pow(ZN.getNqr().toBigInteger());
	}
    public Element generateZN() {
		return ZN.getNqr();
	}

	public static void testPP() {

		double pptime=0;
		long time0 = System.nanoTime();
		for(int i=0;i<10;i++) {
			CompositeOrderPP pp=new CompositeOrderPP();
			System.out.println("GP "+pptime+"ms");
		}
		
	    
	    long time1 = System.nanoTime();
	    pptime += (time1 - time0) / 1_000_000.0;
		
		System.out.println("composite generate a PP in "+pptime/10+"ms");
		
	}
	public static void testexp() {

		double exptime=0;
		CompositeOrderPP pp=new CompositeOrderPP();
		long time0 = System.nanoTime();
		for(int i=0;i<100;i++) {
			Element rE=pp.g_(pp.generateZN());
		}
		
	    
	    long time1 = System.nanoTime();
	    exptime += (time1 - time0) / 1_000_000.0;
		
		System.out.println("composite exp on g1 in "+exptime/100+"ms");
		
	}
	public static void testpairing() {

		double pairtime=0;
		CompositeOrderPP pp=new CompositeOrderPP();
		
		Element ga=pp.g_(pp.generateZN());
		Element gb=pp.g_(pp.generateZN());
		long time0 = System.nanoTime();
		for(int i=0;i<100;i++) {
			Element rE=pp.bp.pairing(ga, gb);
		}
		
	    
	    long time1 = System.nanoTime();
	    pairtime += (time1 - time0) / 1_000_000.0;
		
		System.out.println("composite pairing in "+pairtime/100+"ms");
		
	}
	public static void testgtexp() {

		double pairtime=0;
		CompositeOrderPP pp=new CompositeOrderPP();
		long time0 = System.nanoTime();
		for(int i=0;i<100;i++) {
			Element rE=pp.egg_(pp.generateZN());
		}
		
	    
	    long time1 = System.nanoTime();
	    pairtime += (time1 - time0) / 1_000_000.0;
		
		System.out.println("composite exp on gt in "+pairtime/100+"ms");
		
	}

    public static void testComposite() {
        // Initialize CompositeOrderPP with a path to your custom parameters.
    	testPP();
		testexp();
		testgtexp();
		testpairing();
        // Your further test cases and operations go here
    }
    public static long getSizeInBytes(Object obj) throws Exception {
	    if (obj instanceof Element) {
	        // Use JPBC's built-in serialization method for Elements
	        return ((Element) obj).toBytes().length;
	    } else if (obj instanceof Field) {
	        // Fields themselves may not be serializable, but elements from the field are
	        Element tmp = ((Field) obj).newRandomElement();
	        return tmp.toBytes().length;
	    } else {
	        throw new IllegalArgumentException("Object type not supported for size calculation");
	    }
	}
    public static void testSize() {
    	CompositeOrderPP pp=new CompositeOrderPP();
		try {
	        System.out.println("Size of an element in G1: " + getSizeInBytes(pp.g_(pp.generateZN())) + " bytes");
	        System.out.println("Size of an element in Gt: " + getSizeInBytes(pp.egg_(pp.generateZN())) + " bytes");
	        System.out.println("Size of an element in Zq: " + getSizeInBytes(pp.ZN) + " bytes");
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	}
	public static void main(String arg[]) {
		
		//PP.testPrime();
		//testComposite();
		testSize();
		testComposite();
//		Size of an element in G1: 388 bytes
//		Size of an element in Gt: 388 bytes
//		Size of an element in Zq: 192 bytes
	}
	//testPP();
	//composite generate a PP in 730641.2355ms
	//composite exp on g1 in 6193.0977ms
	//composite exp on gt in 20.1625ms
	//composite pairing in 25740.7ms

}
