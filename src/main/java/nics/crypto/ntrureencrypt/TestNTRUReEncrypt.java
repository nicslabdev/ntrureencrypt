/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package nics.crypto.ntrureencrypt;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.polynomial.IntegerPolynomial;

import java.lang.Byte;

/**
 *
 * @author David Nuñez <dnunez (at) lcc.uma.es>
 */
public class TestNTRUReEncrypt {

    static EncryptionParameters[] eps = {
        EncryptionParameters.EES1087EP2, //0
        EncryptionParameters.EES1087EP2_FAST, //1
        EncryptionParameters.EES1171EP1, // 2
        EncryptionParameters.EES1171EP1_FAST, // 3
        EncryptionParameters.EES1499EP1, // 4
        EncryptionParameters.EES1499EP1_FAST, // 5
        EncryptionParameters.APR2011_439, // 6
        EncryptionParameters.APR2011_439_FAST, // 7
        EncryptionParameters.APR2011_743, // 8
        EncryptionParameters.APR2011_743_FAST // 9
    };

    public static void main(String[] args) throws Exception {
        test3(
            NTRUReEncryptParams.getParams("EES1087EP2_FAST"),
            NTRUReEncryptParams.getDM0("EES1087EP2_FAST")
        );
    }

    public static void testByte() throws Exception {

        BigInteger n = new BigInteger("64523");
        byte[] bytes = n.toByteArray();
        for(int i = 0; i < bytes.length; i++) {
            System.out.println(Arrays.toString(Utils.byteToBitArray(bytes[i])));
        }
        int[] bits = Utils.bigIntegerToBitArray(n);
        System.out.println(Arrays.toString(bits));

    }

    public static void test1() throws Exception {

        byte[] seed = new byte[]{1, 2, 3};

        EncryptionParameters ep = eps[3];   // EES1171EP1_FAST

        NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(ep);

        EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();

        IntegerPolynomial m = ntruReEnc.message(new byte[]{12,34,56});

        IntegerPolynomial c = ntruReEnc.encrypt(kpA.getPublic(), m, seed);

        IntegerPolynomial m2 = ntruReEnc.decrypt(kpA.getPrivate(), c);


        if (Arrays.equals(m.coeffs, m2.coeffs)) {
            System.out.println("Test 1 OK!");
        } else {
            System.out.println("Test 1 Failed!");
        }
    }
    
    public static void test2() throws Exception {

        byte[] seed = new byte[]{1, 2, 3};

        EncryptionParameters ep = eps[3];   // EES1171EP1_FAST

        NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(ep);

        EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();

        IntegerPolynomial m = ntruReEnc.message(new byte[]{12,34,56});

        IntegerPolynomial c = ntruReEnc.encrypt(kpA.getPublic(), m, seed);
        
        EncryptionKeyPair kpB = ntruReEnc.generateKeyPair();

        ReEncryptionKey rk = ntruReEnc.generateReEncryptionKey(kpA, kpB);
        
        IntegerPolynomial cB = ntruReEnc.reEncrypt(rk, c, seed);
        
        IntegerPolynomial m2 = ntruReEnc.decrypt(kpB.getPrivate(), cB);


        if (Arrays.equals(m.coeffs, m2.coeffs)) {
            System.out.println("Test 2 OK!");
        } else {
            System.out.println("Test 2 Failed!");
        }
    }

    public static void test3(EncryptionParameters eps, int dm0) throws Exception {

        System.out.println("\nExecute test with N = " + eps.N + ", q = " + eps.q);

        byte[] seed = new byte[]{0,1,2};

        NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(eps);

        EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();
        EncryptionKeyPair kpB = ntruReEnc.generateKeyPair();
        ReEncryptionKey rk = ntruReEnc.generateReEncryptionKey(kpA, kpB);

        int mLen = 128;
        Random rng = new Random(1234);
        BigInteger m1_bi = new BigInteger(mLen, rng);
        System.out.println("M1");
        System.out.println(m1_bi.toString());
        //IntegerPolynomial m1 = ntruReEnc.encodeMessage(
        //    Utils.bigIntegerToBitArray(m1_bi),
        //    seed,
        //    dm0
        //);
        IntegerPolynomial m1 = ntruReEnc.encodeMessage(m1_bi, seed, dm0);
        BigInteger m2_bi = new BigInteger(mLen, rng);
        System.out.println("M2");
        System.out.println(m2_bi.toString());
        //IntegerPolynomial m2 = ntruReEnc.encodeMessage(
        //    Utils.bigIntegerToBitArray(m2_bi),
        //    seed,
        //    dm0
        //);
        IntegerPolynomial m2 = ntruReEnc.encodeMessage(m2_bi, seed, dm0);

        IntegerPolynomial c1 = ntruReEnc.encrypt(kpA.getPublic(), m1, seed);
        IntegerPolynomial c2 = ntruReEnc.encrypt(kpA.getPublic(), m2, seed);

        c1.add(c2);

        IntegerPolynomial cB = ntruReEnc.reEncrypt(rk, c1, seed);

        IntegerPolynomial dSum = ntruReEnc.decrypt(kpB.getPrivate(), cB);

        //int[] dSum_bin = ntruReEnc.decodeMessagetoBitArray(dSum, mLen);
        BigInteger dSum_bin = ntruReEnc.decodeMessagetoBigInteger(dSum, mLen);
        System.out.println("DSum");
        //System.out.println(Arrays.toString(dSum_bin));
        System.out.println(dSum_bin.toString());

    }

    public static void test4() throws Exception {
        //int mLen = 64;
        //Random rng = new Random(12345);
        //BigInteger m1_bi = new BigInteger(mLen, rng);
        BigInteger m1_bi = new BigInteger("3");

        int[] bitArray = Utils.bigIntegerToBitArray(m1_bi);

        BigInteger m1_target = Utils.bitArrayToBigInteger(bitArray);
        
        System.out.println(m1_bi.toString());
        System.out.println(Arrays.toString(bitArray));
        System.out.println(m1_target.toString());
    }
}
