/*
 * OPSPException.java
 *
 * Created on 28. Januar 2005, 01:37
 */

package org.dyndns.widerstand.OpenPlatform;

/**
 * Describes all defined error codes.
 * @author Widerstand
 */
public class OPSPException extends java.lang.Exception {
    
    private int exceptionCode;
    private String method;
    
    /**
     * The exponent must be 3 or 65537.
     */
    public final static int OPSP_ERROR_WRONG_EXPONENT = 0x8030F003;
    
    /**
     * A file name is invalid.
     */
    public final static int OPSP_ERROR_INVALID_FILENAME = 0x8030F001;
    
    /**
     * A password is invalid.
     */
    public final static int OPSP_ERROR_INVALID_PASSWORD = 0x8030F002;
    
    /**
     * A validation has failed.
     */
    public final static int OPSP_ERROR_VALIDATION_FAILED = 0x8030F000;
    
    /**
     * A necessary object is <code>NULL</code>.
     */
    public final static int OPSP_ERROR_OBJECT_NULL = 0x8030F004;    
    
    /**
     * A APDU command can't be recognized as a valid T=0 protocol Case 1-4 ISO7816-4 APDU.
     */
    public final static int OPSP_ERROR_UNRECOGNIZED_APDU_COMMAND = 0x80301000;
    
    /**
     * The verification of the card cryptogram failed.
     */
    public final static int OPSP_ERROR_CARD_CRYPTOGRAM_VERIFICATION = 0x80302000;
    
    /**
     * The command data is too large for secure messaging.
     */
    public final static int OPSP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE = 0x80303000;
    
    /**
     * The command data is too large.
     */
    public final static int OPSP_ERROR_COMMAND_TOO_LARGE = 0x80303000;
    
    /**
     * A used buffer is too small.
     */
    public final static int OPSP_ERROR_INSUFFICIENT_BUFFER = 0x80304000;
    
    /**
     * More Card Manager, package or application data is available.
     */
    public final static int OPSP_ERROR_MORE_APPLICATION_DATA = 0x80305000;
    
    /**
     * Wrong maximum try limit.
     */
    public final static int OPSP_ERROR_WRONG_TRY_LIMIT = 0x80306000;
    
    /**
     * Wrong PIN length.
     */
    public final static int OPSP_ERROR_WRONG_PIN_LENGTH = 0x80307000;
    
    /**
     * Wrong key version.
     */
    public final static int OPSP_ERROR_WRONG_KEY_VERSION = 0x80308000;
    
    /**
     * Wrong key index.
     */
    public final static int OPSP_ERROR_WRONG_KEY_INDEX = 0x80309000;
    
    /**
     * Wrong key type.
     */
    public final static int OPSP_ERROR_WRONG_KEY_TYPE = 0x8030A000;
    
    /**
     * Key check value reported does not match.
     */
    public final static int OPSP_ERROR_KEY_CHECK_VALUE = 0x8030B000;
    
    /**
     * The combination of key set version and key index is invalid.
     */
    public final static int OPSP_ERROR_INVALID_COMBINATION_KEY_SET_VERSION_KEY_INDEX = 0x8030C000;
    
    /**
     * More key information templates are available.
     */
    public final static int OPSP_ERROR_MORE_KEY_INFORMATION_TEMPLATES = 0x8030D000;
    
    /**
     * The application to load must be less than 32535 bytes.
     */
    public final static int OPSP_ERROR_APPLICATION_TOO_BIG = 0x8030E000;
    
    /**
     * The action was canceled by an SCardCancel request.
     */
    public final static int OPSP_CARD_E_CANCELLED = 0x80100002;
    
    /**
     * The system could not dispose of the media in the requested manner.
     */
    public final static int OPSP_CARD_E_CANT_DISPOSE = 0x8010000E;
    
    /**
     * The smart card does not meet minimal requirements for support.
     */
    public final static int OPSP_CARD_E_CARD_UNSUPPORTED = 0x8010001C;
    
    /**
     * A communications error with the smart card has been detected.
     */
    public final static int OPSP_CARD_E_COMM_DATA_LOST = 0x8010002F;
    
    /**
     * The reader driver did not produce a unique reader name.
     */
    public final static int OPSP_CARD_E_DUPLICATE_READER = 0x8010001B;
    
    /**
     * The data buffer for returned data is too small for the returned data.
     */
    public final static int OPSP_CARD_E_INSUFFICIENT_BUFFER = 0x80100008;
    
    /**
     * An ATR string obtained from the registry is not a valid ATR string.
     */
    public final static int OPSP_CARD_E_INVALID_ATR = 0x80100015;
    
    /**
     * The supplied handle was invalid.
     */
    public final static int OPSP_CARD_E_INVALID_HANDLE = 0x80100003;
    
    /**
     * One or more of the supplied parameters could not be properly interpreted.
     */
    public final static int OPSP_CARD_E_INVALID_PARAMETER = 0x80100004;
    
    /**
     * Registry startup information is missing or invalid.
     */
    public final static int OPSP_CARD_E_INVALID_TARGET = 0x80100005;
    
    /**
     * One or more of the supplied parameter values could not be properly interpreted.
     */
    public final static int OPSP_CARD_E_INVALID_VALUE = 0x80100011;
    
    /**
     * Not enough memory available to complete this command.
     */
    public final static int OPSP_CARD_E_NO_MEMORY = 0x80100006;
    
    /**
     * No smart card reader is available.
     */
    public final static int OPSP_CARD_E_NO_READERS_AVAILABLE = 0x8010002E;
    
    /**
     * The smart card resource manager is not running.
     */
    public final static int OPSP_CARD_E_NO_SERVICE = 0x8010001D;
    
    /**
     * The operation requires a smart card, but no smart card is currently in the device.
     */
    public final static int OPSP_CARD_E_NO_SMARTCARD = 0x8010000C;
    
    /**
     * The reader or card is not ready to accept commands.
     */
    public final static int OPSP_CARD_E_NOT_READY = 0x80100010;
    
    /**
     * An attempt was made to end a non-existent transaction.
     */
    public final static int OPSP_CARD_E_NOT_TRANSACTED = 0x80100016;
    
    /**
     * The PCI receive buffer was too small.
     */
    public final static int OPSP_CARD_E_PCI_TOO_SMALL = 0x80100019;
    
    /**
     * The requested protocols are incompatible with the protocol currently in use with the card.
     */
    public final static int OPSP_CARD_E_PROTO_MISMATCH = 0x8010000F;
    
    /**
     * The specified reader is not currently available for use.
     */
    public final static int OPSP_CARD_E_READER_UNAVAILABLE = 0x80100017;
    
    /**
     * The reader driver does not meet minimal requirements for support.
     */
    public final static int OPSP_CARD_E_READER_UNSUPPORTED = 0x8010001A;
    
    /**
     * The smart card resource manager has shut down.
     */
    public final static int OPSP_CARD_E_SERVICE_STOPPED = 0x8010001E;
    
    /**
     * The smart card cannot be accessed because of other outstanding connections.
     */
    public final static int OPSP_CARD_E_SHARING_VIOLATION = 0x8010000B;
    
    /**
     * The action was canceled by the system, presumably to log off or shut down.
     */
    public final static int OPSP_CARD_E_SYSTEM_CANCELLED = 0x80100012;
    
    /**
     * The user-specified timeout value has expired.
     */
    public final static int OPSP_CARD_E_TIMEOUT = 0x8010000A;
    
    /**
     * An unexpected card error has occurred.
     */
    public final static int OPSP_CARD_E_UNEXPECTED = 0x8010001F;
    
    /**
     * The specified smart card name is not recognized.
     */
    public final static int OPSP_CARD_E_UNKNOWN_CARD = 0x8010000D;
    
    /**
     * The specified reader name is not recognized.
     */
    public final static int OPSP_CARD_E_UNKNOWN_READER = 0x80100009;
    
    /**
     * This smart card does not support the requested feature.
     */
    public final static int OPSP_CARD_E_UNSUPPORTED_FEATURE = 0x8010001F;
    
    /**
     * An internal communications error has been detected.
     */
    public final static int OPSP_CARD_F_COMM_ERROR = 0x80100013;
    
    /**
     * An internal consistency check failed.
     */
    public final static int OPSP_CARD_F_INTERNAL_ERROR = 0x80100001;
    
    /**
     * An internal error has been detected, but the source is unknown.
     */
    public final static int OPSP_CARD_F_UNKNOWN_ERROR = 0x80100014;
    
    /**
     * An internal consistency timer has expired.
     */
    public final static int OPSP_CARD_F_WAITED_TOO_LONG = 0x80100007;
    
    /**
     * No error was encountered.
     */
    public final static int OPSP_CARD_S_SUCCESS = 0x00000000;
    
    /**
     * The action was canceled by the user.
     */
    public final static int OPSP_CARD_W_CANCELLED_BY_USER = 0x8010006E;
    
    /**
     * The smart card has been removed, so that further communication is not possible.
     */
    public final static int OPSP_CARD_W_REMOVED_CARD = 0x80100069;
    
    /**
     * The smart card has been reset, so any shared state information is invalid.
     */
    public final static int OPSP_CARD_W_RESET_CARD = 0x80100068;
    
    /**
     * Power has been removed from the smart card, so that further communication is not possible.
     */
    public final static int OPSP_CARD_W_UNPOWERED_CARD = 0x80100067;
    
    /**
     * The smart card is not responding to a reset.
     */
    public final static int OPSP_CARD_W_UNRESPONSIVE_CARD = 0x80100066;
    
    /**
     * The reader cannot communicate with the card, due to ATR string configuration conflicts.
     */
    public final static int OPSP_CARD_W_UNSUPPORTED_CARD = 0x80100065;
    
    
    /**
     * Error prefix for all ISO7816 errors.
     */
    public final static int OPSP_ISO7816_ERROR_PREFIX = 0x80200000;
    
    /**
     * Response bytes available indicated the last 2 Bytes.
     */
    public final static int OPSP_ISO7816_ERROR_RESPONSE_LENGTH = (OPSP_ISO7816_ERROR_PREFIX | 0x6100);
    
    /**
     * Selected file invalidated.
     */
    public final static int OPSP_ISO7816_ERROR_FILE_INVALIDATED = (OPSP_ISO7816_ERROR_PREFIX | 0x6283);
    
    /**
     * Card life cycle is CM_LOCKED.
     */
    public final static int OPSP_ISO7816_WARNING_CM_LOCKED = (OPSP_ISO7816_ERROR_PREFIX | 0x16283);
    
    /**
     * SELECT FILE Warning: selected file is terminated.
     */
    public final static int OPSP_ISO7816_ERROR_FILE_TERMINATED = (OPSP_ISO7816_ERROR_PREFIX | 0x6285);
    
    /**
     * No information given.
     */
    public final static int OPSP_ISO7816_ERROR_6300 = (OPSP_ISO7816_ERROR_PREFIX | 0x6300);
    
    /**
     * Authentication of host cryptogram failed.
     */
    public final static int OPSP_ISO7816_ERROR_HOST_CRYPTOGRAM_VERIFICATION = (OPSP_ISO7816_ERROR_PREFIX | 0x16300);
    
    /**
     * More data available.
     */
    public final static int OPSP_ISO7816_ERROR_MORE_DATA_AVAILABLE = (OPSP_ISO7816_ERROR_PREFIX | 0x6310);
    
    /**
     * No specific diagnosis.
     */
    public final static int OPSP_ISO7816_ERROR_NOTHING_SPECIFIC = (OPSP_ISO7816_ERROR_PREFIX | 0x6400);
    
    /**
     * Memory failure or EDC check failed.
     */
    public final static int OPSP_ISO7816_ERROR_MEMORY_FAILURE = (OPSP_ISO7816_ERROR_PREFIX | 0x6581);
    
    /**
     * Wrong length.
     */
    public final static int OPSP_ISO7816_ERROR_WRONG_LENGTH = (OPSP_ISO7816_ERROR_PREFIX | 0x6700);
    
    /**
     * Function not supported - Logical channel not supported/open.
     */
    public final static int OPSP_ISO7816_ERROR_CHANNEL_NOT_SUPPORTED = (OPSP_ISO7816_ERROR_PREFIX | 0x6881);
    
    /**
     * Function not supported - Secure messaging not supported.
     */
    public final static int OPSP_ISO7816_ERROR_SECURE_MESSAGING_NOT_SUPPORTED = (OPSP_ISO7816_ERROR_PREFIX | 0x6882);
    
    /**
     * Command not allowed - Conditions of use not satisfied.
     */
    public final static int OPSP_ISO7816_ERROR_CONDITIONS_NOT_SATISFIED = (OPSP_ISO7816_ERROR_PREFIX | 0x6985);
    
    /**
     * The applet to be selected is not multi-selectable, but its context is already active.
     */
    public final static int OPSP_ISO7816_ERROR_NOT_MULTI_SELECTABLE = (OPSP_ISO7816_ERROR_PREFIX | 0x16985);
    
    /**
     * Command not allowed - Security status not satisfied.
     */
    public final static int OPSP_ISO7816_ERROR_SECURITY_STATUS_NOT_SATISFIED = (OPSP_ISO7816_ERROR_PREFIX | 0x6982);
    
    /**
     *
     */
    private final static long OPSP_ISO7816_ERROR_6999 = (OPSP_ISO7816_ERROR_PREFIX | 0x6999);
    
    /**
     * Command not allowed - Security status not satisfied.
     */
    public final static int OPSP_ISO7816_ERROR_SELECTION_REJECTED = (OPSP_ISO7816_ERROR_PREFIX | 0x16999);
    
    /**
     * Wrong data / Incorrect values in command data.
     */
    public final static int OPSP_ISO7816_ERROR_WRONG_DATA = (OPSP_ISO7816_ERROR_PREFIX | 0x6A80);
    
    /**
     * Wrong format for global PIN.
     */
    public final static int OPSP_ISO7816_ERROR_WRONG_GLOBAL_PIN_FORMAT = (OPSP_ISO7816_ERROR_PREFIX | 0x16A80);
    
    /**
     * Function not supported.
     */
    public final static int OPSP_ISO7816_ERROR_FUNC_NOT_SUPPORTED = (OPSP_ISO7816_ERROR_PREFIX | 0x6A81);
    
    /**
     * Card life cycle is CM_LOCKED or selected application was not in a selectable state.
     */
    public final static int OPSP_ISO7816_ERROR_APPLET_NOT_SELECTABLE = (OPSP_ISO7816_ERROR_PREFIX | 0x16A81);
    
    /**
     * File not found.
     */
    public final static int OPSP_ISO7816_ERROR_FILE_NOT_FOUND = (OPSP_ISO7816_ERROR_PREFIX | 0x6A82);// !<
    
    /**
     * The applet to be selected could not be found.
     */
    public final static int OPSP_ISO7816_ERROR_APPLET_NOT_FOUND = (OPSP_ISO7816_ERROR_PREFIX | 0x16A82);
    
    /**
     * Not enough memory space.
     */
    public final static int OPSP_ISO7816_ERROR_NOT_ENOUGH_MEMORY = (OPSP_ISO7816_ERROR_PREFIX | 0x6A84);
    
    /**
     * Incorrect parameters (P1, P2).
     */
    public final static int OPSP_ISO7816_ERROR_INCORRECT_P1P2 = (OPSP_ISO7816_ERROR_PREFIX | 0x6A86);
    
    /**
     * Wrong parameter P2 (PIN try limit).
     */
    public final static int OPSP_ISO7816_ERROR_WRONG_PIN_TRY_LIMIT = (OPSP_ISO7816_ERROR_PREFIX | 0x16A86);
    
    /**
     * Referenced data not found.
     */
    public final static int OPSP_ISO7816_ERROR_DATA_NOT_FOUND = (OPSP_ISO7816_ERROR_PREFIX | 0x6A88);
    
    /**
     * Wrong parameters (P1, P2).
     */
    public final static int OPSP_ISO7816_ERROR_WRONG_P1P2 = (OPSP_ISO7816_ERROR_PREFIX | 0x6B00);
    
    /**
     * Correct expected length (Le) indicated by last 2 Bytes.
     */
    public final static int OPSP_ISO7816_ERROR_CORRECT_LENGTH = (OPSP_ISO7816_ERROR_PREFIX | 0x6C00);
    
    /**
     * Invalid instruction byte / Command not supported or invalid.
     */
    public final static int OPSP_ISO7816_ERROR_INVALID_INS = (OPSP_ISO7816_ERROR_PREFIX | 0x6D00);
    
    /**
     * Wrong CLA byte.
     */
    public final static int OPSP_ISO7816_ERROR_WRONG_CLA = (OPSP_ISO7816_ERROR_PREFIX | 0x6E00);
    
    /**
     * Illegal parameter.
     */
    public final static int OPSP_ISO7816_ERROR_ILLEGAL_PARAMETER = (OPSP_ISO7816_ERROR_PREFIX | 0x6F74);
    
    /**
     * Algorithm not supported.
     */
    public final static int OPSP_ISO7816_ERROR_ALGORITHM_NOT_SUPPORTED = (OPSP_ISO7816_ERROR_PREFIX | 0x9484);
    
    /**
     * Invalid key check value.
     */
    public final static int OPSP_ISO7816_ERROR_INVALID_KEY_CHECK_VALUE = (OPSP_ISO7816_ERROR_PREFIX | 0x9485);
    
    /**
     * General error code for OpenSSL.
     * The OpenSSL error codes are terrible to obtain. There is no comprehensive list.
     * The codes are auto generated and may change (?). So I can not provide a mapping.
     * The last OpenSSL error code can be obtained with a call to {@link OPSPWrapper#getLastOpenSSLErrorCode() OPSPWrapper.getLastOpenSSLErrorCode},
     * a string representation of the last OpenSSL error as usual by a call to {@link OPSPWrapper#stringifyError(int) OPSPWrapper.stringifyError}.
     */
    public final static int OPSP_OPENSSL_ERROR = 0x80400000;
    
    /** Creates a new instance of OPSPException
     * @param method The name of the method in which the exception was thrown.
     */
    public OPSPException(String method, int exceptionCode) {
        super(method+": "+OPSPWrapper.stringifyError(exceptionCode));
        this.method = method;
        this.exceptionCode = exceptionCode;
    }
    
//    public String toString() {
//        if (exceptionCode == OPSPException.OPSP_ERROR_CARDINFO_NULL) {
//            return method+": "+"OPSPCardInfo object is null.";
//        }
//        else if (exceptionCode == OPSPException.OPSP_ERROR_CARDINFO_NULL) {
//            return method+": "+"OPSPSecurityInfo object is null.";
//        } else {
//            return method+": "+OPSPWrapper.stringifyError(exceptionCode);
//        }
//    };
//    
//    public String getMessage() {
//        return toString();
//    }
    
    /**
     * Getter for property exceptionCode.
     * @return Value of property exceptionCode.
     */
    public long getExceptionCode() {
        return exceptionCode;
    }
    
    /**
     * Setter for property exceptionCode.
     * @param exceptionCode New value of property exceptionCode.
     */
    public void setExceptionCode(int exceptionCode) {
        this.exceptionCode = exceptionCode;
    }
    
}
