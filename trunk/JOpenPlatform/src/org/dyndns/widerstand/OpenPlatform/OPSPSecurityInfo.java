/*
 * OPSPSecurityInfo.java
 *
 * Created on 26. Januar 2005, 17:21
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Contains the security information established during
 * {@link OPSPWrapper#mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) OPSPWrapper.mutualAuthentication} method
 * and used during all following transmissions.
 * @author Widerstand
 */
public class OPSPSecurityInfo {
    

    public final static byte encKey[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    public final static byte macKey[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    public final static byte kekKey[] = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    
    /**
     * Command messages are signed and encrypted
     */
    public final static byte OPSP_SECURITY_LEVEL_ENC_MAC = 0x03;
    
    /**
     * Command messages are signed
     */
    public final static byte OPSP_SECURITY_LEVEL_MAC = 0x01;
    
    /**
     * Command messages are plaintext
     */
    public final static byte OPSP_SECURITY_LEVEL_PLAIN = 0x00;
    
    /**
     * The security level
     */
    public byte securityLevel;
    
    /**
     * The MAC session key
     */
    private byte sessionMacKey[];
    
    /**
     * The ENC session key
     */
    private byte sessionEncKey[];
    
    /**
     * The last computed mac
     */
    private byte lastMac[];
    
    /**
     * Creates a new instance of OPSPSecurityInfo
     * @param sessionMacKey The session MAC key.
     * @param sessionEncKey The session ENC key.
     * @param lastMac The last comand MAC.
     * @param securityLevel The security level.
     */
    public OPSPSecurityInfo(byte sessionMacKey[], byte sessionEncKey[], byte lastMac[], byte securityLevel) {
        super();
        this.securityLevel = securityLevel;
        this.sessionEncKey = sessionEncKey;
        this.sessionMacKey = sessionMacKey;
        this.lastMac = lastMac;
    }
    
    /**
     * Getter for property sessionMacKey.
     * @return Value of property sessionMacKey.
     */
    public byte[] getSessionMacKey() {
        return sessionMacKey;
    }
    
    /**
     * Setter for property sessionMacKey.
     * @param sessionMacKey New value of property sessionMacKey.
     */
    public void setSessionMacKey(byte[] sessionMacKey) {
        this.sessionMacKey = new byte[sessionMacKey.length];
        for (int j = 0; j<sessionMacKey.length; j++) {
            this.sessionMacKey[j] = sessionMacKey[j];
        }
    }
    
    /**
     * Getter for property sessionEncKey.
     * @return Value of property sessionEncKey.
     */
    public byte[] getSessionEncKey() {
        return sessionEncKey;
    }
    
    /**
     * Setter for property sessionEncKey.
     * @param sessionEncKey New value of property sessionEncKey.
     */
    public void setSessionEncKey(byte[] sessionEncKey) {
        this.sessionEncKey = new byte[sessionEncKey.length];
        for (int j = 0; j<sessionEncKey.length; j++) {
            this.sessionEncKey[j] = sessionEncKey[j];
        }
    }
    
    /**
     * Getter for property lastMac.
     * @return Value of property lastMac.
     */
    public byte[] getLastMac() {
        return lastMac;
    }
    
    /**
     * Setter for property lastMac.
     * @param lastMac New value of property lastMac.
     */
    public void setLastMac(byte[] lastMac) {
        this.lastMac = new byte[lastMac.length];
        for (int j = 0; j<lastMac.length; j++) {
            this.lastMac[j] = lastMac[j];
        }
    }
    
    /**
     * Returns a string representation of the object.
     * @return The string representation.
     */
    public String toString() {
        return "Session MAC key: "+OPSPUtil.toHexString(sessionEncKey)+"\n"+
                "Session ENC key: "+OPSPUtil.toHexString(sessionMacKey)+"\n"+
                "Last command MAC: "+OPSPUtil.toHexString(lastMac)+"\n"+
                "Security level: "+securityLevel;
    }
}
