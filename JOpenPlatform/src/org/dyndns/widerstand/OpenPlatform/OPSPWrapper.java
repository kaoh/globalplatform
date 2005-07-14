/*
 * OPSPWrapper.java
 *
 * Created on 26. Januar 2005, 11:49
 */

package org.dyndns.widerstand.OpenPlatform;

import java.io.File;

/**
 * Contains all wrapper methods for the Open Platform Library.
 * @author Widerstand
 */
public class OPSPWrapper {
    
    /** Creates a new instance of OPSPWrapper */
    private OPSPWrapper() {
    }
    
    static {
        System.loadLibrary("JOpenPlatformWrapper");
    }
    
    
    /**
     * Returns the last OpenSSL error code.
     * @return The last OpenSSL error code.
     */
    public static native int getLastOpenSSLErrorCode() throws OPSPException;
    
    /**
     * This function establishes a context to the PC/SC resource manager.
     * @return The returned card context.
     */
    public static native long establishContext() throws OPSPException;
    
    /**
     * This function releases the context to the PC/SC resource manager.
     * @param cardContext The valid card context returned by {@link #establishContext() establishContext}
     */
    public static native void releaseContext(long cardContext) throws OPSPException;
    
    /**
     * This function returns a list of currently available readers on the system.
     * @param cardContext The valid card context returned by {@link #establishContext() establishContext}
     * @return The reader names.
     */
    public static native String[] listReaders(long cardContext) throws OPSPException;
    
    /**
     * This function connects to a reader on the system.
     * If something is not working, you may want to change the protocol type.
     * @param cardContext The valid card context returned by {@link #establishContext() establishContext}
     * @param readerName The name of the reader to connect.
     * @param protocol The transmit protocol type to use. Can be OPSP_CARD_PROTOCOL_T0 or OPSP_CARD_PROTOCOL_T1 or both ORed.
     * @return The card handle.
     */
    public static native long cardConnect(long cardContext, String readerName, long protocol) throws OPSPException;
    
    /**
     * This function disconnects a reader on the system.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     */
    public static native void cardDisconnect(long cardHandle) throws OPSPException;
    
    /**
     * Open Platform: Selects an application on a card by AID.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param AID The AID.
     */
    public static native void selectApplication(long cardHandle, OPSPCardConnectionInfo cardInfo,
            byte AID[]) throws OPSPException;
    
    /**
     * Open Platform: Gets the life cycle status of Applications, the Card Manager and Executable Load Files and their privileges.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param cardElement Identifier to retrieve data for Load Files, Applications or the Card Manager.
     * @return The OPSPApplicationData containing AID, life cycle state and privileges.
     */
    public static native OPSPApplicationData[] getStatus(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte cardElement) throws OPSPException;
    
    /**
     * Open Platform: Sets the life cycle status of Applications, Security Domains or the Card Manager.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param cardElement Identifier to retrieve data for Load Files, Applications or the Card Manager.
     * @param AID The AID.
     * @param lifeCycleState The new life cycle state.
     */
    public static native void setStatus(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte cardElement, byte AID[], byte lifeCycleState) throws OPSPException;
    
    /**
     * Formats an error code to a human readable string.
     * @param errorCode The error code.
     * @return String representation of the error code.
     */
    public static native String stringifyError(int errorCode);
    
    /**
     * Retrieves the capabilities of the card reader.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param attributeId The identifier for the requested attribute.
     * @return The attribute information. See PC/SC documentation SCardGetAttrib() for details.
     */
    public static native byte[] getReaderCapabilities(long cardHandle, long attributeId) throws OPSPException;
    
    /**
     * Retrieves the card status.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @return The OPSPCardConnectionInfo containing mechanical card state, protocol information and the ATR.
     */
    public static native OPSPCardConnectionInfo getCardStatus(long cardHandle) throws OPSPException;
    
    /**
     * Open Platform: Mutual authentication.
     * A keySetVersion and keyIndex of 0x00 selects the first available key set version and key index.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param encKey The static encryption key.
     * @param macKey The static MAC key.
     * @param keySetVersion The key set version on the card to use for mutual authentication.
     * @param keyIndex The key index of the encryption key the key set version on the card to use for mutual authentication.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param securityLevel The requested security level.
     * @return The OPSPSecurityInfo.
     */
    public static native OPSPSecurityInfo mutualAuthentication(long cardHandle, byte encKey[], byte macKey[], byte keySetVersion, byte keyIndex, OPSPCardConnectionInfo cardInfo, byte securityLevel) throws OPSPException;
    
    /**
     * Open Platform: Retrieve card data.
     * Retrieves a single card data object from the card identified by identifier.
     * Some cards do not provide some data objects. Some possible identifiers are predefined.
     * See {@link OPSPCardData#OPSP_GET_DATA_ISSUER_BIN OPSPCardData.OPSP_GET_DATA_ISSUER_BIN}. For details about the coding of the response see the programmer's manual
     * of your card.
     * There is a convenience method {@link #getKeyInformationTemplates(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte) getKeyInformationTemplates} to get the key information template(s)
     * containing key set version, key index, key type and key length of the keys.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param identifier Two byte buffer with high and low order tag value for identifying card data object.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @return The card data object.
     */
    public static native byte[] getData(long cardHandle, byte identifier[],
            OPSPCardConnectionInfo cardInfo, OPSPSecurityInfo secInfo) throws OPSPException;
    
    /**
     * Open Platform: Put card data.
     * Puts a single card data object identified by identifier.
     * Some cards do not provide some data objects. Some possible identifiers are predefined.
     * See {@link OPSPCardData#OPSP_GET_DATA_ISSUER_BIN OPSPCardData.OPSP_GET_DATA_ISSUER_BIN}. For details about the coding of the dataObject see the programmer's manual
     * of your card.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param identifier Two byte buffer with high and low order tag value for identifying card data object.
     * @param dataObject The coded data object.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     */
    public static native void putData(long cardHandle, byte identifier[], byte dataObject[],
            OPSPCardConnectionInfo cardInfo, OPSPSecurityInfo secInfo) throws OPSPException;
    
    /**
     * Open Platform: Changes or unblocks the global PIN.
     * The single numbers of the new PIN are encoded as single bytes in the newPIN buffer.
     * The tryLimit must be the range of 0x03 and x0A.
     * The PIN must comprise at least 6 numbers and not exceeding 12 numbers.
     * To unblock the PIN use tryLimit with a value of 0x00. In this case the newPIN buffer is ignored.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param tryLimit The try limit for the PIN.
     * @param newPIN The new PIN.
     * @param kekKey The Key Encryption key (KEK).
     */
    public static native void pinChange(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte tryLimit, byte newPIN[], byte kekKey[]) throws OPSPException;
    
    /**
     * Open Platform: replaces a single 3DES key a key set or adds a new 3DES key.
     * A keySetVersion value of 0x00 adds a new key.
     * Any other value between 0x01 and 0x7f must match an existing key set version.
     * The new key set version defines the key set version a new key belongs to.
     * This can be the same key version or a new not existing key set version.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param keySetVersion An existing key set version.
     * @param keyIndex The position of the key in the key set version.
     * @param newKeySetVersion The new key set version.
     * @param _3desKey The new 3DES key.
     * @param kekKey The key encryption key (KEK) to encrypt the _3desKey.
     */
    public static native void put3desKey(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte keySetVersion, byte keyIndex,
            byte newKeySetVersion, byte _3desKey[], byte kekKey[]) throws OPSPException;
    
    /**
     * Open Platform: replaces a single public RSA key a key set or adds a new public RSA key.
     * A keySetVersion value of 0x00 adds a new key.
     * Any other value between 0x01 and 0x7f must match an existing key set version.
     * The new key set version defines the key set version a new key belongs to.
     * This can be the same key version or a new not existing key set version.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param keySetVersion An existing key set version.
     * @param keyIndex The position of the key in the key set version.
     * @param newKeySetVersion The new key set version.
     * @param PEMKeyFileName A PEM file name with the RSA key.
     * @param passPhrase The passphrase. Must be an ASCII string.
     */
    public static native void putRsaKey(long cardHandle, OPSPSecurityInfo secInfo, OPSPCardConnectionInfo cardInfo,
            byte keySetVersion, byte keyIndex, byte newKeySetVersion, String PEMKeyFileName,
            String passPhrase) throws OPSPException;
    
    /**
     * Open Platform: replaces or adds a secure channel key set consisting of encryption key, MAC key and key encryption.
     * A keySetVersion value of 0x00 adds a new secure channel key set.
     * Any other value between 0x01 and 0x7f must match an existing key set version.
     * The new key set version defines the key set version a the new secure channel keys belongs to.
     * This can be the same key version or a new not existing key set version.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param keySetVersion An existing key set version.
     * @param newKeySetVersion The new key set version.
     * @param newEncKey The new Encryption key.
     * @param newMacKey The new MAC key.
     * @param newKekKey The new key encryption key.
     * @param kekKey The key encryption key (KEK).
     */
    public static native void putSecureChannelKeys(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte keySetVersion, byte newKeySetVersion, byte newEncKey[],
            byte newMacKey[], byte newKekKey[], byte kekKey[]) throws OPSPException;
    
    /**
     * Open Platform: deletes a key or multiple keys.
     * If keyIndex is 0x00 all keys within a keySetVersion are deleted.
     * If keySetVersion is 0x00 all keys with the specified keyIndex are deleted.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param keySetVersion An existing key set version.
     * @param keyIndex An existing key index.
     */
    public static native void deleteKey(long cardHandle, OPSPSecurityInfo secInfo, OPSPCardConnectionInfo cardInfo,
            byte keySetVersion, byte keyIndex) throws OPSPException;
    
    /**
     * Open Platform: Retrieves key information of keys on the card.
     * The card must support the optional report of key information templates.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param keyInformationTemplate The number of the key information template.
     * @return An array of OPSPKeyInformation.
     */
    public static native OPSPKeyInformation[] getKeyInformationTemplates(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte keyInformationTemplate) throws OPSPException;
    
    /**
     * Open Platform: Deletes a package or an applet.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param AIDs An array of byte buffers of AIDs describing the applications and load files to delete.
     * @return If the deletion is performed by a security domain with delegated management privilege a
     * OPSPReceipt for each deleted applet or package is returned, else null.
     */
    public static native OPSPReceiptData[] deleteApplet(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte AIDs[][]) throws OPSPException;
    
    /**
     * Open Platform: Prepares the card for loading an applet.
     * The function assumes that the Card Manager or Security Domain
     * uses an optional load file DAP using the SHA-1 message digest algorithm.
     * The loadFileDAP can be calculated using {@link #calculateLoadFileDAP(OPSPDAPBlock[], String) calculateLoadFileDAP}.
     * In the case of delegated management a Load Token authorizing the INSTALL [for load] must be included.
     * Otherwise loadToken must be null. See {@link #calculateLoadToken(byte[], byte[], byte[], long, long, long, String, String) calculateLoadToken}.
     * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be null, if the card does not need or support this tags.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param packageAID A buffer with AID of the package to INSTALL [for load].
     * @param securityDomainAID A buffer containing the AID of the intended associated Security Domain.
     * @param loadFileDAP The load file DAP of the package to INSTALL [for load].
     * @param loadToken The Load Token. This is a 1024 bit (=80 byte) RSA Signature.
     * @param nonVolatileCodeSpaceLimit The minimum amount of space that must be available to store the package.
     * @param volatileDataSpaceLimit The minimum amount of RAM space that must be available.
     * @param nonVolatileDataSpaceLimit The minimum amount of space for objects of the applet, i.e. the data allocated its lifetime.
     */
    public static native void installForLoad(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte packageAID[], byte securityDomainAID[],
            byte loadFileDAP[], byte loadToken[], long nonVolatileCodeSpaceLimit,
            long volatileDataSpaceLimit, long nonVolatileDataSpaceLimit) throws OPSPException;
    
    /**
     * Open Platform: Function to retrieve the data to sign by the Card Issuer in a Load Token.
     * If you are not the Card Issuer and do not know the token verification private key send this data to the
     * Card Issuer and obtathe RSA signature of the data, i.e. the Load Token.
     * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be null, if the card does not need or support this tags.
     * The parameters must match the parameters of a later installForLoad() method.
     * @param packageAID A buffer containing the package AID.
     * @param securityDomainAID A buffer containing the Security Domain AID.
     * @param loadFileDAP The Load File DAP. The same calculated as installForLoad().
     * @param nonVolatileCodeSpaceLimit The minimum space required to store the applet code.
     * @param volatileDataSpaceLimit The minimum amount of RAM space that must be available.
     * @param nonVolatileDataSpaceLimit The minimum amount of space for objects of the applet, i.e. the data allocated its lifetime.
     * @return The data to sign a Load Token.
     */
    public static native byte[] getLoadTokenSignatureData(byte packageAID[], byte securityDomainAID[],
            byte loadFileDAP[], long nonVolatileCodeSpaceLimit, long volatileDataSpaceLimit,
            long nonVolatileDataSpaceLimit) throws OPSPException;
    
    /**
     * Open Platform: Function to retrieve the data to sign by the Card Issuer in an Install Token.
     * If you are not the Card Issuer and do not know the token verification private key send this data to the
     * Card Issuer and obtain the RSA signature of the data, i.e. the Install Token.
     * volatileDataSpaceLimit can be null, if the card does not need or support this tag.
     * The parameters must match the parameters of a later installForInstall() and installForMakeSelectable() method.
     * @param P1 IN The parameter P1 in the APDU command.
     * <ul>
     * <li> 0x04 for a INSTALL [for install] command </li>
     * <li> 0x08 for an INSTALL [for make selectable] command </li>
     * <li> 0x0C for an INSTALL [for install and make selectable] </li>
     * </ul>
     * @param packageAID A buffer with AID of the package to INSTALL [for install].
     * @param appletClassAID The AID of the applet class the package.
     * @param appletInstanceAID The AID of the installed applet.
     * @param appletPrivileges The applet privileges. Can be an OR of multiple privileges. See {@link OPSPApplicationData OPSPApplicationData}.
     * @param volatileDataSpaceLimit The minimum amount of RAM space that must be available.
     * @param nonVolatileDataSpaceLimit The minimum amount of space for objects of the applet, i.e. the data allocated its lifetime.
     * @param appletInstallParameters Applet install parameters for the install() method of the applet.
     * @return The data to sign a Install Token.
     */
    public static native byte[] getInstallTokenSignatureData(byte P1, byte packageAID[], byte appletClassAID[],
            byte appletInstanceAID[], byte appletPrivileges, long volatileDataSpaceLimit,
            long nonVolatileDataSpaceLimit, byte appletInstallParameters[]) throws OPSPException;
    
    /**
     * Open Platform: Calculates a Load Token using PKCS#1.
     * The parameters must match the parameters of a later installForLoad() method.
     * @param packageAID A buffer containing the package AID.
     * @param securityDomainAID A buffer containing the Security Domain AID.
     * @param loadFileDAP The Load File DAP. The same calculated as installForLoad().
     * @param nonVolatileCodeSpaceLimit The minimum space required to store the package.
     * @param volatileDataSpaceLimit The minimum amount of RAM space that must be available.
     * @param nonVolatileDataSpaceLimit The minimum amount of space for objects of the applet, i.e. the data allocated its lifetime.
     * @return The calculated Load Token. A 1024 bit RSA signature.
     * @param PEMKeyFileName A PEM file name with the private RSA key.
     * @param passPhrase The passphrase. Must be an ASCII string.
     */
    public static native byte[] calculateLoadToken(byte packageAID[], byte securityDomainAID[],
            byte loadFileDAP[], long nonVolatileCodeSpaceLimit, long volatileDataSpaceLimit,
            long nonVolatileDataSpaceLimit, String PEMKeyFileName, String passPhrase) throws OPSPException;
    
    /**
     * Open Platform: Calculates an Install Token using PKCS#1.
     * The parameters must match the parameters of a later installForInstall(), installForMakeSelectable() and
     * installForInstallAndMakeSelectable() method.
     * @param P1 IN The parameter P1 in the APDU command.
     * <ul>
     * <li> 0x04 for a INSTALL [for install] command </li>
     * <li> 0x08 for an INSTALL [for make selectable] command </li>
     * <li> 0x0C for an INSTALL [for install and make selectable] </li>
     * </ul>
     * @param packageAID A buffer with AID of the package to INSTALL [for load].
     * @param appletClassAID The AID of the applet class the package.
     * @param appletInstanceAID The AID of the installed applet.
     * @param appletPrivileges The applet privileges. Can be an OR of multiple privileges. See {@link OPSPApplicationData OPSPApplicationData}.
     * @param volatileDataSpaceLimit The minimum amount of RAM space that must be available.
     * @param nonVolatileDataSpaceLimit The minimum amount of space for objects of the applet, i.e. the data allocated its lifetime.
     * @param appletInstallParameters Applet install parameters for the install() method of the applet.
     * @return The calculated Install Token. A 1024 bit RSA signature.
     * @param PEMKeyFileName A PEM file name with the private RSA key.
     * @param passPhrase The passphrase. Must be an ASCII string.
     */
    public static native byte[] calculateInstallToken(byte P1, byte packageAID[], byte appletClassAID[],
            byte appletInstanceAID[], byte appletPrivileges, long volatileDataSpaceLimit,
            long nonVolatileDataSpaceLimit, byte appletInstallParameters[], String PEMKeyFileName,
            String passPhrase) throws OPSPException;
    
    /**
     * Open Platform: Calculates a Load File DAP.
     * This is a hash of the load file with SHA-1.
     * A load file consists of 0 to n Load File Data Block DAP blocks and a mandatory
     * load file data block, e.g. a CAP file.
     * If no DAP blocks are necessary the dapBlock must be null.
     * The dapBlock(s) can be calculated using calculate3desDap() or calculateRsaDap().
     * If the DAP block(s) are already calculated they must be parsed into an OPSPDAPBlock.
     * If the DAP block(s) are already prefixing the CAPFile following the Open Platform Specification 2.0.1',
     * the whole CAPFile including the DAP block(s) is sufficient, the dapBlock must be null.
     * @param dapBlock An array of OPSPDAPBlock(s).
     * @param CAPFileName The name of the CAP file to hash.
     * @return The hash value.
     */
    public static native byte[] calculateLoadFileDAP(OPSPDAPBlock dapBlock[], String CAPFileName) throws OPSPException;
    
    /**
     * Open Platform: Loads a package (containing an applet) to the card.
     * An installForLoad() must precede.
     * The DAP block(s) must be the same block(s) and the same order like {@link #calculateLoadFileDAP(OPSPDAPBlock[], String) calculateLoadFileDAP}.
     * If no DAP blocks are necessary the dapBlock must be null.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param dapBlock An array of OPSPDAPBlock(s).
     * @param CAPFileName The name of the CAP file.
     * @return If the deletion is performed by a Security Domain with delegated management privilege a
     * OPSPReceipt is returned, else null.
     */
    public static native OPSPReceiptData loadApplet(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, OPSPDAPBlock dapBlock[], String CAPFileName) throws OPSPException;
    
    /**
     * Open Platform: Installs an applet on the card.
     * the case of delegated management an Install Token authorizing the INSTALL [for install] must be included.
     * Otherwise installToken must be null. See {@link #calculateInstallToken(byte[], byte[], byte[], byte, long, long, byte[], String, String) calculateInstallToken}.
     * volatileDataSpaceLimit and nonVolatileDataSpaceLimit can be null, if the card does not need or support this tag.
     * For Security domains look your manual what parameters are necessary.
     * If the tag for applet install parameters is mandatory for your card, but you have no install parameters
     * for the install() method of the applet anyway you have to use at least a dummy parameter.
     * If appletClassAID is null and appletClassAIDLength is null appletInstanceAID is assumed for appletClassAID.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param packageAID A buffer with AID of the package to INSTALL [for load].
     * @param appletClassAID The AID of the applet class the package.
     * @param appletInstanceAID The AID of the installed applet.
     * @param appletPrivileges The applet privileges. Can be an OR of multiple privileges. See {@link OPSPApplicationData OPSPApplicationData}.
     * @param volatileDataSpaceLimit The minimum amount of RAM space that must be available.
     * @param nonVolatileDataSpaceLimit The minimum amount of space for objects of the applet, i.e. the data allocated its lifetime.
     * @param appletInstallParameters Applet install parameters for the install() method of the applet.
     * @param installToken The Install Token. This is a 1024 bit (=80 byte) RSA Signature.
     * @return If the deletion is performed by a security domawith delegated management privilege a
     * OPSPReceipt is returned, else null.
     */
    public static native OPSPReceiptData installForInstall(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte packageAID[], byte appletClassAID[],
            byte appletInstanceAID[], byte appletPrivileges, long volatileDataSpaceLimit,
            long nonVolatileDataSpaceLimit, byte appletInstallParameters[],
            byte installToken[]) throws OPSPException;
    
    /**
     * Open Platform: Makes an installed applet selectable.
     * In the case of delegated management an Install Token authorizing the INSTALL [for make selectable] must be included.
     * Otherwise installToken must be null.
     * For Security domains look your manual what parameters are necessary.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param appletInstanceAID The AID of the installed applet or security domain.
     * @param appletPrivileges The applet privileges. Can be an OR of multiple privileges. See {@link OPSPApplicationData OPSPApplicationData}.
     * @param installToken The Install Token. This is a 1024 bit (=80 byte) RSA Signature.
     * @return If the deletion is performed by a security domawith delegated management privilege a
     * OPSPReceipt is returned, else null.
     */
    public static native OPSPReceiptData installForMakeSelectable(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte appletInstanceAID[],
            byte appletPrivileges, byte installToken[]) throws OPSPException;
    
    /**
     * Open Platform: Installs and makes an installed applet selectable.
     * In the case of delegated management an Install Token authorizing the INSTALL [for install and make selectable] must be included.
     * Otherwise installToken must be null.
     * For Security domains look your manual what parameters are necessary.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param appletInstanceAID The AID of the installed applet or security domain.
     * @param appletPrivileges The applet privileges. Can be an OR of multiple privileges. See {@link OPSPApplicationData OPSPApplicationData}.
     * @param installToken The Install Token. This is a 1024 bit (=80 byte) RSA Signature.
     * @return If the deletion is performed by a security domawith delegated management privilege a
     * OPSPReceipt is returned, else null.
     */
    public static native OPSPReceiptData installForInstallAndMakeSelectable(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte packageAID[], byte appletClassAID[],
            byte appletInstanceAID[], byte appletPrivileges, long volatileDataSpaceLimit,
            long nonVolatileDataSpaceLimit, byte appletInstallParameters[],
            byte installToken[]) throws OPSPException;
    
    /**
     * Open Platform: Adds a key set for Delegated Management.
     * A keySetVersion value of 0x00 adds a new secure channel key set.
     * Any other value between 0x01 and 0x7f must match an existing key set version.
     * The new key set version defines the key set version a the new secure channel keys belongs to.
     * This can be the same key version or a new not existing key set version.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param keySetVersion An existing key set version.
     * @param newKeySetVersion The new key set version.
     * @param PEMKeyFileName A PEM file name with the public RSA key.
     * @param passPhrase The passphrase. Must be an ASCII string.
     * @param receiptGenerationKey The new Receipt Generation key.
     * @param kekKey The key encryption key (KEK).
     */
    public static native void putDelegatedManagementKeys(long cardHandle, OPSPSecurityInfo secInfo,
            OPSPCardConnectionInfo cardInfo, byte keySetVersion, byte newKeySetVersion,
            String PEMKeyFileName, String passPhrase,
            byte receiptGenerationKey[], byte kekKey[]) throws OPSPException;
    
    /** Sends an application protocol data unit.
     * @param cardHandle The card handle obtained by {@link #cardConnect(long, String, long) cardConnect}.
     * @param capdu The command APDU.
     * @param cardInfo The OPSPCardConnectionInfo returned by {@link #getCardStatus(long) getCardStatus}.
     * @param secInfo The OPSPSecurityInfo returned by {@link #mutualAuthentication(long, byte[], byte[], byte, byte, OPSPCardConnectionInfo, byte) mutualAuthentication}.
     * @return rapdu The response APDU.
     */
    public static native byte[] sendAPDU(long cardHandle, byte capdu[], OPSPCardConnectionInfo cardInfo,
            OPSPSecurityInfo secInfo) throws OPSPException;
    
    /** Open Platform: Calculates a Load File Data Block DAP using 3DES.
     * If a security domain has DAP verification privilege the security domain validates this DAP.
     * @param securityDomainAID A buffer containing the Security Domain AID.
     * @param CAPFileName The name of the CAP file to calculate the DAP for.
     * @param DAPVerificationKey The key to calculate the DAP.
     * @return The returned OPSPDAPBlock.
     */
    public static native OPSPDAPBlock calculate3desDAP(byte securityDomainAID[], String CAPFileName,
            byte DAPVerificationKey[]) throws OPSPException;
    
    /** Open Platform: Calculates a Load File Data Block DAP using SHA-1 and PKCS#1 (RSA).
     * If a security domain has DAP verification privilege the security domain validates this DAP.
     * @param securityDomainAID A buffer containing the Security Domain AID.
     * @param CAPFileName The name of the CAP file to calculate the DAP for.
     * @param PEMKeyFileName A PEM file name with the private RSA key.
     * @param passPhrase The passphrase. Must be an ASCII string.
     * @return The returned OPSPDAPBlock.
     */
    public static native OPSPDAPBlock calculateRsaDAP(byte securityDomainAID[], String CAPFileName,
            String PEMKeyFileName, String passPhrase) throws OPSPException;
    
    /** Open Platform: Validates a Load Receipt.
     * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
     * You may keep track of it.
     * @param confirmationCounter The confirmation counter.
     * @param cardUniqueData The card unique data (?).
     * @param receiptGenerationKey The 3DES key to generate the receipt.
     * @param receiptData The OPSPReceiptData containing the receipt returned
     * from {@link #deleteApplet(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte[][]) deleteApplet} to verify.
     * @param AID A buffer with AID of the application which was deleted.
     * @return true if the receipt is valid.
     */
    public static native boolean validateDeleteReceipt(long confirmationCounter, byte cardUniqueData[],
            byte receiptGenerationKey[], OPSPReceiptData receiptData,
            byte AID[]) throws OPSPException;
    
    /** Open Platform: Validates an Install Receipt.
     * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
     * You may keep track of it.
     * @param confirmationCounter The confirmation counter.
     * @param cardUniqueData The card unique data (?).
     * @param receiptGenerationKey The 3DES key to generate the receipt.
     * @param receiptData The OPSPReceiptData containing the receipt returned
     * from {@link #installForInstall(long, OPSPSecurityInfo, OPSPCardConnectionInfo, byte[], byte[], byte[], byte, long, long, byte[], byte[]) installForInstall} to verify.
     * @param packageAID A buffer with AID of the package which was INSTALL [for install].
     * @param appletInstanceAID The AID of the installed applet.
     * @return true if the receipt is valid.
     */
    public static native boolean validateInstallReceipt(long confirmationCounter, byte cardUniqueData[],
            byte receiptGenerationKey[], OPSPReceiptData receiptData,
            byte packageAID[],
            byte appletInstanceAID[]) throws OPSPException;
    
    /** Open Platform: Validates a Load Receipt.
     * Each time a receipt is generated the confirmation counter is incremented by the Card Manager.
     * You may keep track of it.
     * @param confirmationCounter The confirmation counter.
     * @param cardUniqueData The card unique data (?).
     * @param receiptGenerationKey The 3DES key to generate the receipt.
     * @param receiptData The OPSPReceiptData containing the receipt returned
     * from {@link #loadApplet(long, OPSPSecurityInfo, OPSPCardConnectionInfo, OPSPDAPBlock[], String) loadApplet} to verify.
     * @param packageAID A buffer with AID of the package which was INSTALL [for load].
     * @param securityDomainAID A buffer containing the AID of the associated Security Domain.
     * @return true if the receipt is valid.
     */
    public static native boolean validateLoadReceipt(long confirmationCounter, byte cardUniqueData[],
            byte receiptGenerationKey[], OPSPReceiptData receiptData,
            byte packageAID[], byte securityDomainAID[]) throws OPSPException;
    
    
}

