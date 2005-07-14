/*
 * Util.java
 *
 * Created on 7. Februar 2005, 01:09
 */

package org.dyndns.widerstand.OpenPlatform;

import java.io.*;

/**
 * Some helper functions.
 * @author Karsten Ohme
 */
public class OPSPUtil {
    
    /**
     * The symbols for the hex digits.
     */
    private static final char[] HEX_DIGITS =
    {
        '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
    };
    
    /** Creates a new instance of Util */
    private OPSPUtil() {
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
    
    /**
     * Saves a Load File Data Block DAP.
     * @param file The file to save.
     * @param dapBlock The OPSPDAPBlock to be saved.
     */
    public static void saveDAP(File file, OPSPDAPBlock dapBlock) throws IOException {
        BufferedOutputStream out = null;
        try {
            out = new BufferedOutputStream(new FileOutputStream(file));
            byte securityDomain[] = dapBlock.getSecurityDomainAID();
            byte signature[] = dapBlock.getSignature();
            out.write(securityDomain.length);
            out.write(securityDomain);
            out.write(signature.length);
            out.write(signature);
        } catch (IOException e) {
            throw e;
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }
    
    
    /**
     * Saves a Load or Install Token.
     * @param file The file to save.
     * @param token The token to be saved.
     */
    public static void saveToken(File file, byte[] token) throws IOException {
        BufferedOutputStream out = null;
        try {
            out = new BufferedOutputStream(new FileOutputStream(file));
            out.write(token);
        } catch (IOException e) {
            throw e;
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }
    
    /**
     * Loads a Load or Install Token.
     * @param fileName The file name of the token to load.
     * @return The loaded token.
     */
    public static byte[] loadToken(String fileName) throws IOException {
        File file = new File(fileName);
        int size = (int)file.length();
        if (size != 128) throw new IOException("Invalid token file format.");
        BufferedInputStream input = null;
        byte token[] = null;
        try {
            input = new BufferedInputStream(new FileInputStream(file));
            token = new byte[size];
            input.read(token, 0, size);
        } catch (IOException e) {
            throw e;
        } finally {
            input.close();
        }
        return token;
    }
    
    /**
     * Loads a 2 key 3DES key.
     * @param file The file of the token to load.
     * @return The loaded 3DES key.
     */
    public static byte[] load3DES(File file) throws IOException {
        int size = (int)file.length();
        if (size != 16) throw new IOException("Invalid 3DES key file format.");
        byte key[] = null;
        BufferedInputStream input = null;
        try {
            input = new BufferedInputStream(new FileInputStream(file));
            key = new byte[size];
            input.read(key, 0, size);
        } catch (IOException e) {
            throw e;
        } finally {
            if (input != null) {
                input.close();
            }
        }
        return key;
    }
    
    /**
     * Tries to parse a file into a OPSPDAPBlock instance.
     * @param fileName The file to parse.
     * @return The OPSPDAPBlock instance.
     */
    public static OPSPDAPBlock loadDAP(String fileName) throws IOException {
        File file = new File(fileName);
        BufferedInputStream in = null;
        byte securityDomain[] = null;
        byte signature[] = null;
        try {
            in = new BufferedInputStream(new FileInputStream(file));
            int size = in.read();
            if ((size == -1) || (size > 16)) throw new IOException("Invalid DAP file format.");
            securityDomain = new byte[size];
            int read = 0;
            int tmp = 0;
            while (read < size) {
                tmp = in.read(securityDomain, read, size-read);
                if (tmp == -1) throw new IOException("Invalid DAP file format.");
                read+=tmp;
            }
            size = in.read();
            if ((size == -1) || ((size != 128) && (size != 16)))  throw new IOException("Invalid DAP file format.");
            signature = new byte[size];
            read = 0;
            tmp = 0;
            while (read < size) {
                tmp = in.read(signature, read, size-read);
                if (tmp == -1) throw new IOException("Invalid DAP file format.");
                read+=tmp;
            }
        } catch (IOException e) {
            throw e;
        } finally {
            if (in != null) {
                in.close();
            }
        }
        return new OPSPDAPBlock(securityDomain, signature);
    }
    
    /**
     * Saves a OPSPReceiptData.
     * @param file The file to save.
     * @param receiptData The OPSPReceiptData to be saved.
     */
    public static void saveOPSPReceiptData(File file,
            OPSPReceiptData receiptData) throws IOException {
        BufferedOutputStream out = null;
        try {
            out = new BufferedOutputStream(new FileOutputStream(file));
            byte receipt[] = receiptData.getReceipt();
            byte confirmationCounter[] = receiptData.getConfirmationCounter();
            byte cardUniqueData[] = receiptData.getCardUniqueData();
            out.write(receipt.length);
            out.write(receipt);
            out.write(confirmationCounter.length);
            out.write(confirmationCounter);
            out.write(cardUniqueData.length);
            out.write(cardUniqueData);
        } catch (IOException e) {
            throw e;
        } finally {
            if (out != null) {
                out.close();
            }
        }
    }
    
    /**
     * Tries to parse a file into a OPSPReceiptData instance.
     * @param fileName The file to parse.
     * @return The OPSPReceiptData instance.
     */
    public static OPSPReceiptData loadOPSPReceiptData(String fileName) throws IOException {
        File file = new File(fileName);
        BufferedInputStream in = null;
        byte receipt[] = null;
        byte confirmationCounter[] = null;
        byte cardUniqueData[] = null;
        try {
            in = new BufferedInputStream(new FileInputStream(file));
            int size = in.read();
            if ((size == -1) || (size != 8)) throw new IOException("Invalid Receipt Data file format.");
            receipt = new byte[size];
            int read = 0;
            int tmp = 0;
            while (read < size) {
                tmp = in.read(receipt, read, size-read);
                if (tmp == -1) throw new IOException("Invalid Receipt Data file format.");
                read+=tmp;
            }
            size = in.read();
            if ((size == -1) || (size != 2)) throw new IOException("Invalid Receipt Data file format.");
            confirmationCounter = new byte[size];
            read = 0;
            tmp = 0;
            while (read < size) {
                tmp = in.read(confirmationCounter, read, size-read);
                if (tmp == -1) throw new IOException("Invalid Receipt Data file format.");
                read+=tmp;
            }
            size = in.read();
            if ((size == -1) || (size != 10)) throw new IOException("Invalid Receipt Data file format.");
            confirmationCounter = new byte[size];
            read = 0;
            tmp = 0;
            while (read < size) {
                tmp = in.read(cardUniqueData, read, size-read);
                if (tmp == -1) throw new IOException("Invalid Receipt Data file format.");
                read+=tmp;
            }
        } catch (IOException e) {
            throw e;
        } finally {
            if (in != null) {
                in.close();
            }
        }
        return new OPSPReceiptData(receipt, confirmationCounter, cardUniqueData);
    }
    
}
