/*
 * Util.java
 *
 * Created on 7. Februar 2005, 01:09
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Some helper functions.
 * @author Widerstand
 */
public class Util {
    
    /**
     * The symbols for the hex digits.
     */
    private static final char[] HEX_DIGITS =
    {
        '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
    };
    
    /** Creates a new instance of Util */
    private Util() {
    }
    
    /**
     * Parses a hex string into a byte array.
     * @param hex The hex string.
     * @return The byte array presentation of the hex string.
     */
    public static byte[] bytesFromHexString(String hex) throws NumberFormatException  {
        if (hex.length() == 0) return null;
        String myhex = hex + " ";
        int len = myhex.length();
        if ((len % 3) != 0) throw new NumberFormatException();
        byte[] buf = new byte[len / 3];
        int i = 0, j = 0;
        while (i < len) {
            try {
                buf[j++] = (byte) ((fromDigit(myhex.charAt(i++)) << 4) |
                        fromDigit(myhex.charAt(i++)));
            } catch (IllegalArgumentException e) {
                throw new NumberFormatException();
            }
            if (myhex.charAt(i++) != ' ') throw new NumberFormatException();
        }
        return buf;
    }
    
    /**
     * Returns the value of the hex character.
     * @param ch The hex character
     * @return The value of the hex character.
     */
    private static int fromDigit(char ch) {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'A' && ch <= 'F')
            return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f')
            return ch - 'a' + 10;
        throw new IllegalArgumentException("invalid hex digit '" + ch + "'");
    }
    
    /**
     * Returns a hex string representing the byte array.
     * @param ba The byte array to hexify.
     * @return The hex string.
     */
    public static String toHexString( byte[] ba ) {
        int length = ba.length;
        char[] buf = new char[length * 3];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ba[i++];
            buf[j++] = HEX_DIGITS[(k >> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k       & 0x0F];
            buf[j++] = ' ';
        }
        return new String(buf, 0, buf.length-1);
    }
    
}
