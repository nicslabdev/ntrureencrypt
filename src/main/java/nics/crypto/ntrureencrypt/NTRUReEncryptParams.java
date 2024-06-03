package nics.crypto.ntrureencrypt;

import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.IndexGenerator;
import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;

public class NTRUReEncryptParams extends EncryptionParameters {
    
    /**
     * Constructs a parameter set that uses ternary private keys (i.e. </code>polyType=SIMPLE</code>).
     * @param N            number of polynomial coefficients
     * @param q            modulus
     * @param df           number of ones in the private polynomial <code>f</code>
     * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param maxM1        maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. Values greater than zero cause the constant coefficient of the message to always be zero.
     * @param db           number of random bits to prepend to the message; should be a multiple of 8
     * @param c            a parameter for the Index Generation Function ({@link IndexGenerator})
     * @param minCallsR    minimum number of hash calls for the IGF to make
     * @param minCallsMask minimum number of calls to generate the masking polynomial
     * @param hashSeed     whether to hash the seed in the MGF first (true) or use the seed directly (false)
     * @param oid          three bytes that uniquely identify the parameter set
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
     * @param fastFp       whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>. The <code>MessageDigest</code> must support the <code>getDigestLength()</code> method.
     */
    public NTRUReEncryptParams(int N, int q, int df, int dm0, int maxM1, int db, int c, int minCallsR, int minCallsMask, boolean hashSeed, byte[] oid, boolean sparse, boolean fastFp, String hashAlg) {
        super(N, q, df, dm0, maxM1, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg);
    }

    /**
     * Constructs a parameter set that uses product-form private keys (i.e. </code>polyType=PRODUCT</code>).
     * @param N number of polynomial coefficients
     * @param q modulus
     * @param df1          number of ones in the private polynomial <code>f1</code>
     * @param df2          number of ones in the private polynomial <code>f2</code>
     * @param df3          number of ones in the private polynomial <code>f3</code>
     * @param dm0          minimum acceptable number of -1's, 0's, and 1's in the polynomial <code>m'</code> in the last encryption step
     * @param maxM1        maximum absolute value of mTrin.sumCoeffs() or zero to disable this check. Values greater than zero cause the constant coefficient of the message to always be zero.
     * @param db           number of random bits to prepend to the message; should be a multiple of 8
     * @param c            a parameter for the Index Generation Function ({@link IndexGenerator})
     * @param minCallsR    minimum number of hash calls for the IGF to make
     * @param minCallsMask minimum number of calls to generate the masking polynomial
     * @param hashSeed     whether to hash the seed in the MGF first (true) or use the seed directly (false)
     * @param oid          three bytes that uniquely identify the parameter set
     * @param sparse       whether to treat ternary polynomials as sparsely populated ({@link SparseTernaryPolynomial} vs {@link DenseTernaryPolynomial})
     * @param fastFp       whether <code>f=1+p*F</code> for a ternary <code>F</code> (true) or <code>f</code> is ternary (false)
     * @param hashAlg      a valid identifier for a <code>java.security.MessageDigest</code> instance such as <code>SHA-256</code>
     */
    public NTRUReEncryptParams(int N, int q, int df1, int df2, int df3, int dm0, int maxM1, int db, int c, int minCallsR, int minCallsMask, boolean hashSeed, byte[] oid, boolean sparse, boolean fastFp, String hashAlg) {
        super(N, q, df1, df2, df3, dm0, maxM1, db, c, minCallsR, minCallsMask, hashSeed, oid, sparse, fastFp, hashAlg);
    }

    // Interface to get a parameter instance
    public static EncryptionParameters getParams(String implementation) {
        switch (implementation) {
            case "EES1087EP2":
                return EES1087EP2;
            case "EES1087EP2_FAST":
                return EES1087EP2_FAST;
            case "EES1171EP1":
                return EES1171EP1;
            case "EES1171EP1_FAST":
                return EES1171EP1_FAST;
            case "EES1499EP1":
                return EES1499EP1;
            case "EES1499EP1_FAST":
                return EES1499EP1_FAST;
            case "APR2011_439":
                return APR2011_439;
            case "APR2011_439_FAST":
                return APR2011_439_FAST;
            case "APR2011_743":
                return APR2011_743;
            case "APR2011_743_FAST":
                return APR2011_743_FAST;
            default:
                return null;
        }
    }

    // Interface to get the dm0 value of a parameter instance
    public static int getDM0(String implementation) {
        switch (implementation) {
            case "EES1087EP2":
                return 120;
            case "EES1087EP2_FAST":
                return 120;
            case "EES1171EP1":
                return 106;
            case "EES1171EP1_FAST":
                return 106;
            case "EES1499EP1":
                return 79;
            case "EES1499EP1_FAST":
                return 79;
            case "APR2011_439":
                return 130;
            case "APR2011_439_FAST":
                return 130;
            case "APR2011_743":
                return 220;
            case "APR2011_743_FAST":
                return 220;
            default:
                return 0;
        }
    }

}
