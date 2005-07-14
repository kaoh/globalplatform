/*
 * OPSPKeyInformation.java
 *
 * Created on 26. Januar 2005, 18:03
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Contains the information data for a key retrieved in the
 * {@link OPSPWrapper#getKeyInformationTemplates(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte) OPSPWrapper.getKeyInformationTemplates}
 * method.
 * @author Widerstand
 */
public class OPSPKeyInformation {
        
    /**
     * key type RSA
     */
    public final static byte OPSP_KEY_TYPE_RSA = (byte)0xA1;
    
    /**
     * key type 3DES
     */
    public final static byte OPSP_KEY_TYPE_3DES = (byte)0x81;
    
    /**
     * The key set version
     */
    public byte keySetVersion;
    
    /**
     * The key index
     */
    public byte keyIndex;
    
    /**
     * The key type
     */
    public byte keyType;
    
    /**
     * The key length
     */
    public byte keyLength;
    
    /** Creates a new instance of OPSPKeyInformation 
     * @param keySetVersion The key set version of the key.
     * @param keyIndex The index in the key set version.
     * @param keyType The type of the key.
     * @param keyLength The length of the key.
     */
    public OPSPKeyInformation(byte keySetVersion, byte keyIndex, byte keyType, byte keyLength) {
        super();
        this.keyIndex = keyIndex;
        this.keySetVersion = keySetVersion;
        this.keyType = keyType;
        this.keyLength = keyLength;
    }
    
}
