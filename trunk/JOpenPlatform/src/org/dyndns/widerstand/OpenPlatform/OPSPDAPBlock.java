/*
 * OPSPDAPBlock.java
 *
 * Created on 26. Januar 2005, 18:25
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Contains the relevant data for an Open Platform Load File Data Block DAP block.
 * @author Widerstand
 */
public class OPSPDAPBlock {
    
    /**
     * The AID of the Security Domain
     */
    private byte securityDomainAID[];
    
    /**
     * Getter for property securityDomainAID.
     * @return Value of property securityDomainAID.
     */
    public byte[] getSecurityDomainAID() {
        return securityDomainAID;
    }
    
    /**
     * Setter for property securityDomainAID.
     * @param securityDomainAID New value of property securityDomainAID.
     */
    public void setSecurityDomainAID(byte securityDomainAID[]) {
        this.securityDomainAID = securityDomainAID;
    }
    
    /**
     * The signature
     */
    private byte signature[];
    
    /**
     * Getter for property signature.
     * @return Value of property signature.
     */
    public byte[] getSignature() {
        return signature;
    }
    
    /**
     * Setter for property signature.
     * @param signature New value of property signature.
     */
    public void setSignature(byte signature[]) {
        this.signature = signature;
    }
    
    /** Creates a new instance of OPSPDAPBlock 
     * @param securityDomainAID The AID of the security domain the signature is for.
     * @param signature The signature for the Load File Data Block.
     */
    public OPSPDAPBlock(byte securityDomainAID[], byte signature[]) {
        super();
        this.signature = signature;
        this.securityDomainAID = securityDomainAID;
    }
    
}
