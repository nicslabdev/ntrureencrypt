package nics.crypto.ntrureencrypt;

import java.math.BigInteger;

public class Utils {
    
    /**
     * Converts a Java byte to a bit array
     * 
     * @param b     A Java byte
     * @return      A bit array as int[] with values in {0,1}
     */
    public static int[] byteToBitArray(byte b) {
        int[] bitArray = new int[8]; // An array to hold the bits (0 or 1)
        for (int i = 0; i < 8; i++) {
            // Shift right and mask with 1 to get the bit value at position i
            bitArray[7 - i] = (b >> i) & 1;
        }
        return bitArray;
    }

    /**
     * Converts a BigInteger in an int array (binary form)
     * 
     * @param value
     * @return          A binary int array with the LSB in cell 0
     */
    public static int[] bigIntegerToBitArray(BigInteger value) {
        
        byte[] bytes = value.toByteArray();

        // Invert the byte array
        for (int i = 0; i < bytes.length / 2; i++) {
            byte temp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = temp;
        }

        // Check if there is an additional byte of 0s
        int BL = bytes.length;
        if(value.bitLength() <= (bytes.length * 8) - 8) {
            BL = bytes.length - 1;
        }

        int[] bits = new int[BL * 8];

        // For each byte
        for(int i = 0; i < BL; i++) {
            
            // Invert the bits in this byte
            int[] thisBits = Utils.byteToBitArray(bytes[i]);
            for (int j = 0; j < thisBits.length / 2; j++) {
                int temp = thisBits[j];
                thisBits[j] = thisBits[thisBits.length - 1 - j];
                thisBits[thisBits.length - 1 - j] = temp;
            }

            // Fill the result
            for (int j = 0; j < 8; j++) {
                bits[i * 8 + j] = thisBits[j];
            }
        }
        return bits;
    }

    /**
     * Converts a bit array (binary form) to a BigInteger
     * 
     * @param bits  A binary int array with the LSB in cell 0
     * @return      A BigInteger representation of the input bit array
     */
    public static BigInteger bitArrayToBigInteger(int[] bits) {
        // Calculate the number of bytes needed
        int byteLength = (bits.length + 7) / 8;
        byte[] bytes = new byte[byteLength];
        
        // Iterate over the bit array and set the corresponding bits in the byte array
        for (int i = 0; i < bits.length; i++) {
            int byteIndex = i / 8;
            int bitIndex = i % 8;
            if (bits[i] == 1) {
                bytes[byteIndex] |= (1 << bitIndex);
            }
        }
        
        // Invert the byte array
        for (int i = 0; i < bytes.length / 2; i++) {
            byte temp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = temp;
        }
        
        // Convert the byte array to a BigInteger
        return new BigInteger(1, bytes);
    }

}
