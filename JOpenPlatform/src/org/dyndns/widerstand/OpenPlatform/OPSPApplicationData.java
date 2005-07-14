/*
 * OPSPApplicationData.java
 *
 * Created on 26. Januar 2005, 17:45
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Contains the application data retrieved in {@link OPSPWrapper#getStatus(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte) OPSPWrapper.getStatus} method
 * @author Widerstand
 */
public class OPSPApplicationData {
    
    /**
     * The AID
     */
    private byte AID[];
    
    /**
     * Getter for property AID.
     * @return Value of property AID.
     */
    public byte[] getAID() {
        return AID;
    }
    
    /**
     * Setter for property AID.
     * @param AID New value of property AID.
     */
    public void setAID(byte AID[]) {
        this.AID = AID;
    }
    
    /**
     * The Card Manager, package or application life cycle state.
     */
    public byte lifeCycleState;
    
    /**
     * The Card Manager or applet privileges.
     */
    public byte privileges;
    
    
    /** Creates a new instance of OPSPApplicationData 
     * @param AID The application identifier.
     * @param lifeCycleState The life cycle state.
     * @param privileges The privileges.
     */
    public OPSPApplicationData(byte AID[], byte lifeCycleState, byte privileges) {
        super();
        this.lifeCycleState = lifeCycleState;
        this.privileges = privileges;
        this.AID = AID;
    }
    
    /**
     * Returns a string representation of the object.
     * @return The string representation.
     */
    public String toString() {
        return "AID: "+OPSPUtil.toHexString(AID)+"\n"+
                "Life cycle state: "+lifeCycleState+"\n"+
                "Privileges: "+privileges;
    }
    
}
