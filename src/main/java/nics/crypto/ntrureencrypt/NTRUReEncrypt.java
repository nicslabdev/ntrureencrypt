/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package nics.crypto.ntrureencrypt;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.NtruEncrypt;
import net.sf.ntru.exception.NtruException;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;

/**
 *
 * @author David Nuñez <dnunez (at) lcc.uma.es>
 */
public class NTRUReEncrypt {

    
    EncryptionParameters params;
    NtruEncrypt ntru;
    
    private IntegerPolynomial one;
    
    static boolean out = true;

    /**
     * Constructs a new instance with a set of encryption parameters.
     *
     * @param params encryption parameters
     */
    public NTRUReEncrypt(EncryptionParameters params) {
        ntru = new NtruEncrypt(params);
        this.params = params;
        
        one = new IntegerPolynomial(params.N);
        one.coeffs[0] = 1;
    }

    private Polynomial generateBlindingPolynomial(byte[] seed) throws Exception {

//        for(Method m : ntru.getClass().getDeclaredMethods()){
//            System.out.println(m.getName());
//        }
        Method m = ntru.getClass().getDeclaredMethod("generateBlindingPoly", byte[].class);
        m.setAccessible(true);
        return (Polynomial) m.invoke(ntru, seed);
    }

    private static IntegerPolynomial extractH(EncryptionPublicKey pub) throws Exception {
        Field f = EncryptionPublicKey.class.getDeclaredField("h");
        f.setAccessible(true);
        return ((IntegerPolynomial) f.get(pub)).toIntegerPolynomial();
    }

    public EncryptionKeyPair generateKeyPair() {
        return this.ntru.generateKeyPair();
    }

    
    
    public ReEncryptionKey generateReEncryptionKey(EncryptionPrivateKey pA, EncryptionPrivateKey pB) throws Exception {
        
        IntegerPolynomial fA = privatePolynomial(pA);
        IntegerPolynomial fB = privatePolynomial(pB);
        
        return new ReEncryptionKey(fA, fB, params.q);
    }
    
    public ReEncryptionKey generateReEncryptionKey(EncryptionKeyPair pA, EncryptionKeyPair pB) throws Exception {
        return generateReEncryptionKey(pA.getPrivate(), pB.getPrivate());
    }

    public IntegerPolynomial encrypt(EncryptionPublicKey pub, IntegerPolynomial m, byte[] seed) throws Exception {

        Polynomial r = generateBlindingPolynomial(seed);

        IntegerPolynomial h = extractH(pub);
        
        IntegerPolynomial e = r.mult(h);
        
        e.add(m);
        
        e.ensurePositive(params.q);
        
        return e;

    }

    public IntegerPolynomial reEncrypt(ReEncryptionKey rk, IntegerPolynomial c, byte[] seed) throws Exception {

        Polynomial r = generateBlindingPolynomial(seed);



        IntegerPolynomial ruido = r.toIntegerPolynomial();
        ruido.mult(3);
        ruido.modCenter(params.q);


        IntegerPolynomial c_prime = c.mult(rk.rk);
        c_prime.add(ruido);
        c_prime.ensurePositive(params.q);

        return c_prime;

    }

    public IntegerPolynomial decrypt(EncryptionPrivateKey priv, IntegerPolynomial c) throws Exception {

        IntegerPolynomial f = privatePolynomial(priv);

        IntegerPolynomial a = c.toIntegerPolynomial().mult(f);
        
        a.modCenter(params.q);
        
        IntegerPolynomial m = a.toIntegerPolynomial();
        
        m.mod3();
        
        return m;

    }

    public static void out(String s) {
        if (out) {
            System.out.println(s);
        }
    }

    public IntegerPolynomial message(byte[] msg) {
        // Crea un mensaje aleatorio con dm 0's, dm 1's y dm -1's.
        IntegerPolynomial m = new IntegerPolynomial(params.N);
        Random rand = new SecureRandom(msg);
        ArrayList<Integer> list = new ArrayList<Integer>();

        int dm0 = 106; // params.dm0; FIXED FROM ees1171ep1

        while (list.size() < dm0 * 3) {
            Integer i = rand.nextInt(params.N);
            if (!list.contains(i)) {
                list.add(i);
            }
        }
        for (int j = 0; j < dm0; j++) {
            m.coeffs[list.get(j)] = 0;
        }
        for (int j = dm0; j < 2 * dm0; j++) {
            m.coeffs[list.get(j)] = -1;
        }
        for (int j = 2 * dm0; j < 3 * dm0; j++) {
            m.coeffs[list.get(j)] = 1;
        }
        return m;
    }

    /** 
     * Encodes a binary message into the mLen less significant coefficients of a ternary polynomial of length N
     * 
     * @param msg   binary message encoded as int array {0,1}*
     * @param seed  a seed to initialize the secure random to generate ternary coefficients
     * @param dm0   the minimum number of coefficients that must be -1, 0, or 1
     * 
     * @return      the binary message encoded as a polynomial with ternary coefficients
     */

    // TODO: adapt the randomness generator to use a different distribution based on the number of {0,1}s in the input
    // TODO: apply different forms of encoding, e.g., even/odd cells, less/more significant coefficients...

    public IntegerPolynomial encodeMessage(int[] msg, byte[] seed, int dm0) {
        
        // In the worst case, the message is all 0's or 1's. The rest of N coeffs are not enough to fulfil the minimum dm0 for {-1 , 0, 1}.
        if((params.N - msg.length) < dm0 * 2) {
            throw new NtruException("Message too long.");
        }

        int mLen = msg.length;
        IntegerPolynomial m = new IntegerPolynomial(params.N);
        Random rand = new SecureRandom(seed);
        ArrayList<Integer> list = new ArrayList<Integer>();

        for(int i = 0; i < mLen; i++) {
            m.coeffs[i] = msg[i];
        }

        boolean ok_m = true;
        do{
            for(int i = mLen; i < params.N; i++) {
                m.coeffs[i] = rand.nextInt(3) - 1;
            }
            if (m.count(-1) < dm0)
                ok_m = false;
            if (m.count(0) < dm0)
                ok_m = false;
            if (m.count(1) < dm0)
                ok_m = false;

        } while(!ok_m);

        return m;
    }

    /**
     * Interface to encode a BigInteger decimal number inside a ternary polynomial
     * 
     * @param msg
     * @param seed
     * @param dm0
     * @return
     */
    public IntegerPolynomial encodeMessage(BigInteger msg, byte[] seed, int dm0) {
        int[] binaryMsg = Utils.bigIntegerToBitArray(msg);
        return this.encodeMessage(binaryMsg, seed, dm0);
    }

    /** 
     * Decodes a ternary polynomial to a binary message, performing the corresponding carries of binary addition if needed
     * Carries can exist if the message recovered is the result of the addition of two messages using the homomorphic property of NTRU
     * REMARK: only a single addition is supported, otherwise the result cannot be recovered
     * 
     * @param encM  a polynomial with ternary coefficients
     * @param mLen  the mLen coefficients of encM with smaller degree are the encoded message
     * 
     * @return      the recovered message after applying the addition carries (as int[] of binary data)
     */

    public int[] decodeMessagetoBitArray(IntegerPolynomial encM, int mLen) {

        int[] res = new int[mLen + 1];
        for(int j = 0; j < mLen; j++) {
            res[j] = (encM.coeffs[j] == -1) ? 2 : encM.coeffs[j];
        }

        int carry = 0;
        for(int j = 0; j < res.length - 1; j++) {
            res[j] += carry;
            if(res[j] >= 2) {
                res[j] -= 2;
                carry = 1;
            } else {
                carry = 0;
            }
        }
        res[mLen] = carry;

        return res;
    }

    public BigInteger decodeMessagetoBigInteger(IntegerPolynomial encM, int mLen) {
        int[] decoded = this.decodeMessagetoBitArray(encM, mLen);
        return Utils.bitArrayToBigInteger(decoded);
    }

    public static IntegerPolynomial extractF(EncryptionPrivateKey priv) throws Exception {
        Field f = EncryptionPrivateKey.class.getDeclaredField("t");
        f.setAccessible(true);
        return ((Polynomial) f.get(priv)).toIntegerPolynomial();
    }

    public IntegerPolynomial privatePolynomial(EncryptionPrivateKey priv) throws Exception {        

        IntegerPolynomial f = extractF(priv);
        f.mult(3);
        f.add(one);

        return f;
    }

}