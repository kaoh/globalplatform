/*
 * OPSPReceipt.java
 *
 * Created on 26. Januar 2005, 18:11
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Contains the receipt DAP and related data.
 * @author Widerstand
 */
public class OPSPReceiptData {
    
    /**
     * The confirmation counter buffer
     */
    private byte confirmationCounter[];
    
    /**
     * Card unique data buffer
     */
    private byte cardUniqueData[];
    
    /**
     * The receipt DAP.
     */
    private byte[] receipt;
    
    /** Creates a new instance of OPSPReceipt 
     * @param receipt The receipt.
     * @param confirmationCounter The confirmation counter.
     * @param cardUniqueData The unique card data.
     */
    public OPSPReceiptData(byte receipt[], byte confirmationCounter[], byte cardUniqueData[]) {
        this.receipt = receipt;
        this.cardUniqueData = cardUniqueData;
        this.confirmationCounter = confirmationCounter;
    }
    
    /**
     * Getter for property confirmationCounter.
     * @return Value of property confirmationCounter.
     */
    public byte[] getConfirmationCounter() {
        return confirmationCounter;
    }
    
    /**
     * Setter for property confirmationCounter.
     * @param confirmationCounter New value of property confirmationCounter.
     */
    public void setConfirmationCounter(byte confirmationCounter[]) {
        this.confirmationCounter = confirmationCounter;
    }
    
    /**
     * Getter for property cardUniqueData.
     * @return Value of property cardUniqueData.
     */
    public byte[] getCardUniqueData() {
        return cardUniqueData;
    }
    
    /**
     * Setter for property cardUniqueData.
     * @param cardUniqueData New value of property cardUniqueData.
     */
    public void setCardUniqueData(byte[] cardUniqueData) {
        this.cardUniqueData = cardUniqueData;
    }
    
    /**
     * Getter for property receipt.
     * @return Value of property receipt.
     */
    public byte[] getReceipt() {
        
        return this.receipt;
    }
    
    /**
     * Setter for property receipt.
     * @param receipt New value of property receipt.
     */
    public void setReceipt(byte[] receipt) {
        
        this.receipt = receipt;
    }
    
}
