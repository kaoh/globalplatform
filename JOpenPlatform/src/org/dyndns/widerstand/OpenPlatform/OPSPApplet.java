/*
 * OPSPApplication.java
 *
 * Created on 29. Januar 2005, 19:19
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Contains identifiers for application privileges, life cycle states and other 
 * associated application specific data.
 * @author Widerstand
 */
public class OPSPApplet {

    /**
     * The AID of the Card Manager defined by Open Platform specification.
     */
    public static final byte OPSP_CARD_MANAGER_AID[] = {(byte)0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00};
    /**
     * Executable Load File is logically deleted
     */
    public final static byte OPSP_LIFE_CYCLE_LOAD_FILE_LOGICALLY_DELETED = 0x00;
    
    /**
     * Executable Load File is loaded
     */
    public final static byte OPSP_LIFE_CYCLE_LOAD_FILE_LOADED = 0x01;
    
    /**
     * Card is OP ready
     */
    public final static byte OPSP_LIFE_CYCLE_CARD_MANAGER_OP_READY = 0x01;
    
    /**
     * Card is initialized
     */
    public final static byte OPSP_LIFE_CYCLE_CARD_MANAGER_INITIALIZED = 0x07;
    
    /**
     * Card is in secured state
     */
    public final static byte OPSP_LIFE_CYCLE_CARD_MANAGER_SECURED = 0x0f;
    
    /**
     * Card is locked
     */
    public final static byte OPSP_LIFE_CYCLE_CARD_MANAGER_CM_LOCKED = 0x7f;
    
    /**
     * Card is terminated
     */
    public final static byte OPSP_LIFE_CYCLE_CARD_MANAGER_TERMINATED = (byte)0xff;
    
    /**
     * Application is logically deleted
     */
    public final static byte OPSP_LIFE_CYCLE_APPLICATION_LOGICALLY_DELETED = 0x00;
    
    /**
     * Application is installed
     */
    public final static byte OPSP_LIFE_CYCLE_APPLICATION_INSTALLED = 0x03;
    
    /**
     * Application is selectable
     */
    public final static byte OPSP_LIFE_CYCLE_APPLICATION_SELECTABLE = 0x07;
    
    /**
     * Application is personalized
     */
    public final static byte OPSP_LIFE_CYCLE_APPLICATION_PERSONALIZED = 0x0f;
    
    /**
     * Application is blocked
     */
    public final static byte OPSP_LIFE_CYCLE_APPLICATION_BLOCKED = 0x7f;
    
    /**
     * Application is locked
     */
    public final static byte OPSP_LIFE_CYCLE_APPLICATION_LOCKED = (byte)0xff;
    
    /**
     * Application is security domain
     */
    public final static byte OPSP_APPLICATION_PRIVILEGE_SECURITY_DOMAIN = (byte)0x80;
    
    /**
     * Application can require DAP verification for loading and installating applications
     */
    public final static byte OPSP_APPLICATION_PRIVILEGE_DAP_VERIFICATION = 0x40;
    
    /**
     * Security domain has delegeted management right
     */
    public final static byte OPSP_APPLICATION_PRIVILEGE_DELEGATED_MANAGEMENT = 0x20;
    
    /**
     * Application can lock the Card Manager
     */
    public final static byte OPSP_APPLICATION_PRIVILEGE_CARD_MANAGER_LOCK_PRIVILEGE = 0x10;
    
    /**
     * Application can terminate the card
     */
    public final static byte OPSP_APPLICATION_PRIVILEGE_CARD_MANAGER_TERMINATE_PRIVILEGE = 0x08;
    
    /**
     * Application is default selected
     */
    public final static byte OPSP_APPLICATION_PRIVILEGE_DEFAULT_SELECTED = 0x04;
    
    /**
     * Application can change global PIN
     */
    public final static byte OPSP_APPLICATION_PRIVILEGE_PIN_CHANGE_PRIVILEGE = 0x02;
    
    /**
     * Security domain requires DAP verification for loading and installating applications
     */
    public final static byte OPSP_APPLICATION_PRIVILEGE_MANDATED_DAP_VERIFICATION = 0x01;
    
    /**
     * Indicate Applications or Security Domains in {@link OPSPWrapper#getStatus(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte) OPSPWrapper.getStatus}
     * or {@link OPSPWrapper#setStatus(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte, byte[], byte) OPSPWrapper.setStatus}
     */
    public final static byte OPSP_STATUS_APPLICATIONS = 0x40;
    
    /**
     * Indicate Card Manager in {@link OPSPWrapper#getStatus(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte) OPSPWrapper.getStatus}
     * or{@link OPSPWrapper#setStatus(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte, byte[], byte) OPSPWrapper.setStatus}
     */
    public final static byte OPSP_STATUS_CARD_MANAGER = (byte)0x80;
    
    /**
     * Request OPSPApplicationData for Executable Load Files in {@link OPSPWrapper#getStatus(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte) OPSPWrapper.getStatus}
     */
    public final static byte OPSP_STATUS_LOAD_FILES = 0x20;

    /** Creates a new instance of OPSPApplet 
     */
    private OPSPApplet() {
    }    
        
}
