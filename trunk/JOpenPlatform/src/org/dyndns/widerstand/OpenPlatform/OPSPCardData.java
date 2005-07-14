/*
 * OPSPCard.java
 *
 * Created on 29. Januar 2005, 21:14
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Contains some identifiers for card data.
 * @author Widerstand
 */
public class OPSPCardData {
    
    /** Creates a new instance of OPSPCard */
    private OPSPCardData() {
    }
    
    /**
     * Issuer BIN, if Card Manager selected.
     */
    public final static byte OPSP_GET_DATA_ISSUER_BIN[] = {0x00, 0x42};
    
    /**
     * Application provider identification number, if Security Domain selected.
     */
    public final static byte OPSP_GET_DATA_APPLICATION_PROVIDER_IDENTIFICATION_NUMBER[] = {0x00, 0x42};
    
    /**
     * Card issuer data, if Card Manager selected.
     */
    public final static byte OPSP_GET_DATA_ISSUER_DATA[] = {0x00, 0x45};
    
    /**
     * Security domain image number, if Security Domain selected.
     */
    public final static byte OPSP_GET_DATA_SECURITY_DOMAIN_IMAGE_NUMBER[] = {0x00, 0x45};
    
    /**
     * Change Card Manager AID, if Card Manager selected.
     */
    public final static byte OPSP_GET_DATA_CARD_MANAGER_AID[] = {0x00, 0x4F};
    
    /**
     * Change Security Domain AID, if Security Domain selected.
     */
    public final static byte OPSP_GET_DATA_SECURITY_DOMAIN_AID[] = {0x00, 0x4F};
    
    /**
     * Card recognition data.
     */
    public final static byte OPSP_GET_DATA_CARD_RECOGNITION_DATA[] = {0x00, 0x66};
    
    /**
     * Sequence Counter of the default Key Version Number.
     */
    public final static byte OPSP_GET_DATA_SEQUENCE_COUNTER_DEFAULT_KEY_VERSION[] = {0x00, (byte)0xC1};
    
    /**
     * Confirmation Counter.
     */
    public final static byte OPSP_GET_DATA_CONFIRMATION_COUNTER[] = {0x00, (byte)0xC2};
    
    /**
     * Free EEPROM memory space.
     */
    public final static byte OPSP_GET_DATA_FREE_EEPROM_MEMORY_SPACE[] = {0x00, (byte)0xC6};
    
    /**
     * Free transient Clear on Reset memory space (COR RAM).
     */
    public final static byte OPSP_GET_DATA_FREE_COR_RAM[] = {0x00, (byte)0xC7};
    
    /**
     * Diversification data.
     */
    public final static byte OPSP_BYTE_DIVERSIFICATION_DATA[] = {0x00, (byte)0xCF};
    
    /**
     * Key Information Template of first 31 keys.
     * Next templates can be obtained with the tag 0x0x 0xE0, where x > 0.
     */
    public final static byte OPSP_GET_DATA_KEY_INFORMATION_TEMPLATE[] = {0x00, (byte)0xE0};
    
    /**
     * CPLC personalization date.
     */
    public final static byte OPSP_GET_DATA_CPLC_PERSONALIZATION_DATE[] = {(byte)0x9F, 0x66};
    
    /**
     * CPLC pre-personalization date.
     */
    public final static byte OPSP_GET_DATA_CPLC_PRE_PERSONALIZATION_DATE[] = {(byte)0x9F, 0x67};
    
    /**
     * CPLC ICC manufacturer, embedding date.
     */
    public final static byte OPSP_GET_DATA_CPLC_ICC_MANUFACTURER_EMBEDDING_DATE[] = {(byte)0x9F, 0x68};
    
    /**
     * CPLC module fabricator, module packaging date.
     */
    public final static byte OPSP_GET_DATA_CPLC_MODULE_FABRICATOR_PACKAGING_DATE[] = {(byte)0x9F, 0x69};
    
    /**
     * CPLC fabrication date, serail number, batch identifier.
     */
    public final static byte OPSP_GET_DATA_CPLC_FABRICATION_DATE_SERIAL_NUMBER_BATCH_IDENTIFIER[] = {(byte)0x9F, 0x6A};
    
    /**
     * Whole CPLC data from ROM and EEPROM.
     */
    public final static byte OPSP_GET_DATA_CPLC_WHOLE_CPLC[] = {(byte)0x9F, 0x7F};
    
    /**
     * File Control Information (FCI) discretionary data.
     */
    public final static byte OPSP_GET_DATA_FCI_DATA[] = {(byte)0xBF, 0x0C};
    
    /**
     * Data for protocol change.
     */
    public final static byte OPSP_GET_DATA_PROTOCOL[] = {(byte)0xDF, 0x70};
    
    /**
     * Change ATR historical bytes.
     */
    public final static byte OPSP_GET_DATA_ATR_HISTRORICAL_BYTES[] = {(byte)0xDF, 0x71};
    
    /**
     * EF<sub>prod</sub> data initialization fingerprint.
     */
    public final static byte OPSP_GET_DATA_EF_PROD_DATA_INITIALIZATION_FINGERPRINT[] = {(byte)0xDF, 0x76};
    
    /**
     * EF<sub>prod</sub> data initialization data.
     */
    public final static byte OPSP_GET_DATA_EF_PROD_DATA_INITIALIZATION_DATA[] = {(byte)0xDF, 0x77};
    
    /**
     * EF<sub>prod</sub> data production key index.
     */
    public final static byte OPSP_GET_DATA_EF_PROD_DATA_PRODUCTION_KEY_INDEX[] = {(byte)0xDF, 0x78};
    
    /**
     * EF<sub>prod</sub> data protocol version.
     */
    public final static byte OPSP_GET_DATA_EF_PROD_DATA_PROTOCOL_VERSION[] = {(byte)0xDF, 0x79};
    
    /**
     * EF<sub>prod</sub> data checksum.
     */
    public final static byte OPSP_GET_DATA_EF_PROD_DATA_CHECKSUM[] = {(byte)0xDF, 0x7A};
    
    /**
     * EF<sub>prod</sub> data software version.
     */
    public final static byte OPSP_GET_DATA_EF_PROD_DATA_SOFTWARE_VERSION[] = {(byte)0xDF, 0x7B};
    
    /**
     * EF<sub>prod</sub> data RFU.
     */
    public final static byte OPSP_GET_DATA_EF_PROD_DATA_RFU[] = {(byte)0xDF, 0x7C};
    
    /**
     * EF<sub>prod</sub> data profile with profile version.
     */
    public final static byte OPSP_GET_DATA_EF_PROD_DATA_PROFILE_WITH_PROFILE_VERSION[] = {(byte)0xDF, 0x7D};
    
    /**
     * EF<sub>prod</sub> data location, machine number, date, time.
     */
    public final static byte OPSP_GET_DATA_EF_PROD_DATA_LOCATION_MACHINE_DATE_TIME[] = {(byte)0xDF, 0x7E};
    
    /**
     * Whole EF<sub>prod</sub> data block (39 Byte).
     */
    public final static byte OPSP_GET_DATA_WHOLE_EF_PROD[] = {(byte)0xDF, 0x7F};
    
}
