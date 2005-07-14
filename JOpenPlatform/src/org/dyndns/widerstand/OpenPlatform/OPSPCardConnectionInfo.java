/*
 * OPSPCardConnectionInfo.java
 *
 * Created on 26. Januar 2005, 17:12
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Contains information about the card state.
 * @author Widerstand
 */
public class OPSPCardConnectionInfo {
    
    /**
     * The communication protocol T0.
     */
    public final static long OPSP_CARD_PROTOCOL_T0 = 1;
    
    /**
     * The communication protocol T1.
     */
    public final static long OPSP_CARD_PROTOCOL_T1 = 2;

    /**
     * There is no card in the reader
     */
    public static final long OPSP_CARD_ABSENT = 1;
    
    /**
     * There is a card in the reader, but it has not been moved into position for use
     */
    public static final long OPSP_CARD_PRESENT = 2;
    
    /**
     * There is a card in the reader in position for use. The card is not powered
     */
    public static final long OPSP_CARD_SWALLOWED = 3;
    
    /**
     * Power is being provided to the card, but the reader driver is unaware of the mode of the card
     */
    public static final long OPSP_CARD_POWERED = 4;
    
    /**
     * The card has been reset and is awaiting PTS negotiation
     */
    public static final long OPSP_CARD_NEGOTIABLE = 5;
    
    /**
     * The card has been reset and specific communication protocols have been established
     */
    public static final long OPSP_CARD_SPECIFIC = 6;
    
    /**
     * The Answer To Reset from the card
     */
    private byte ATR[];
    
    /**
     * Getter for property ATR.
     * @return Value of property ATR.
     */
    public byte[] getATR() {
        return ATR;
    }
    
    /**
     * Setter for property ATR.
     * @param ATR New value of property ATR.
     */
    public void setATR(byte ATR[]) {
        this.ATR = new byte[ATR.length];
        for (int j = 0; j<ATR.length; j++) {
            this.ATR[j] = ATR[j];
        }
    }
    
    /**
     * The card protocol T0 or T1
     */
    public long protocol;
    
    /**
     * The mechanical state of the card:
     * <ul>
     * <li> {@link #OPSP_CARD_ABSENT}
     * <li> {@link #OPSP_CARD_PRESENT}
     * <li> {@link #OPSP_CARD_SWALLOWED}
     * <li> {@link #OPSP_CARD_POWERED}
     * <li> {@link #OPSP_CARD_NEGOTIABLE}
     * <li> {@link #OPSP_CARD_SPECIFIC}
     * </ul>
     */
    public long state;
      
    /** Creates a new instance of OPSPCardConnectionInfo
     * @param ATR The Answer To Reset
     * @param protocol The protocol
     * @param state The state of the card
     */
    public OPSPCardConnectionInfo(byte ATR[], long protocol, long state) {
        super();
        this.protocol = protocol;
        this.state = state;
        this.ATR = ATR;
    }

    /**
     * Returns a string representation of the object.
     * @return The string representation.
     */
    public String toString() {
        return "ATR: "+OPSPUtil.toHexString(ATR)+"\n"+
                "Protocol: "+protocol+"\n"+
                "State: "+state;
    }

}
