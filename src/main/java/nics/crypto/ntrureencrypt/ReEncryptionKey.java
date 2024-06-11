/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package nics.crypto.ntrureencrypt;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import net.sf.ntru.exception.NtruException;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.util.ArrayEncoder;

/**
 *
 * @author David Nuñez <dnunez (at) lcc.uma.es>
 */
public class ReEncryptionKey {

    public int N;
    public int q;
    public IntegerPolynomial rk;
    
    public ReEncryptionKey(IntegerPolynomial rk, int q) {
        this.N = rk.coeffs.length;
        this.q = q;
        this.rk = rk.clone();
    }

    public ReEncryptionKey(byte[] b) {
        this(new ByteArrayInputStream(b));
    }

    public ReEncryptionKey(InputStream is) {
        DataInputStream dataStream = new DataInputStream(is);
        try {
            N = dataStream.readShort();
            q = dataStream.readShort();
            rk = IntegerPolynomial.fromBinary(dataStream, N, q);
        } catch (IOException e) {
            throw new NtruException(e);
        }
    }
    
    public ReEncryptionKey(IntegerPolynomial fA, IntegerPolynomial fB, int q) {
        
        //if(fA.coeffs.length != fB.coeffs.length) {
        //    throw new Exception("Selected private keys do not have the same length.");
        //}

        this.q = q;
        this.N = fA.coeffs.length;

        IntegerPolynomial fBinv = fB.toIntegerPolynomial().invertFq(q);
        rk = fA.toIntegerPolynomial().mult(fBinv);
        
    }

    public byte[] getEncoded() {
        return ArrayEncoder.concatenate(ArrayEncoder.toByteArray(this.N), ArrayEncoder.toByteArray(this.q), rk.toBinary(this.q));
    }
    
}
