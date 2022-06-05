% GPSHELL(1) 2.2.0 | GPShell Documentation

# NAME

**gpshell** - command line tool for the management of GlobalPlatform compliant smart cards

# SYNOPSIS

| **gpshell** _scriptfile_

# DESCRIPTION

gpshell can manage applications on smart cards supporting the GlobalPlatform.
This comprises the installation and deletion of applications, getting the
applications status and card data. These applications are practical always Java Card applets.
Additional key management commands are provided.

The most common way to use gpshell is a script file. But it is also possible to read the commands from stdin if no script file is provided.

Within a script environment variables can be accessed with the syntax `${ENV_VAR_NAME}`.

Reading the commands from stdin allows to feed in the commands dynamically and use conditionals when using the [Expect](https://en.wikipedia.org/wiki/Expect) pattern. Tools
are available for a variety of script languages, shells and programming languages. Example are to support environment variables and handle results and output conditionally.

There are several `txt` example scripts provided which gets installed into `usr/local/share/docs` or `/home/linuxbrew/.linuxbrew/opt/globalplatform/share/doc/gpshell1/` or can be found [online](https://github.com/kaoh/globalplatform/tree/master/gpshell).

# COMMANDS

__mode_201__

:    Set protocol mode to OpenPlatform 2.0.1. This is the default.

__mode_211__

:    Set protocol mode to GlobalPlatform 2.1.1 and later

__visa_key_derivation__

:   For cards which use the VISA key derivation scheme for the key calculation, like GemXpresso Pro, Palmera Protect or some JCOP cards this must be set.

__emv_cps11_key_derivation__

:    For cards which uses the EMV CPS 1.1 key derivation scheme for the key calculation, like a Sm@rtCafe Expert 3.0 this must be set.

__enable_trace__

:    Enable APDU trace

You will see the sent APDUs in clear text. The last two bytes of the response are the response code. A response code of 9000 means success, otherwise the response code indicates an error. This may be OK when deleting a non existing applet or package.

__enable_timer__

:    Enable the logging of the execution times of commands.

__establish_context__

:    Establish context. This must always be executed before connecting to a card.

__card_connect__ -reader *readerName* -protocol *protocol*

:    Connect to card in the reader with *readerName*. By default protocol is 0 = T0.

__card_connect__ -readerNumber *x* -protocol *protocol*

:    Connect to card in the *x* th reader in the system. By default protocol is 0 = T0.

__open_sc__ -keyind *x* -keyver *x* -key *key* -mac_key *mac-key* -enc_key *enc-key* -kek_key *kek-key* -security *securityLevel* -scp *protocol* -scpimpl *impl* -keyDerivation *derivation*

:    Open a secure channel

For OpenPlatform 2.0.1' cards only -keyind -keyver -mac_key and -enc_key are necessary.

For GlobalPlatform 2.1.1 and later cards -scp and -scpimpl should not be necessary to supply. You must also specify -kek_key.

If the card supports a Secure Channel Protocol Implementation with only one base key, specify this key with -key and omit the others.

If the card uses a key derivation mechanism you must enable the derivation mode with the -keyDerivation option and you must specify with -key the master (mother) key. -kek_key, -mac_key and -enc_key are not relevant is this case. See the section Options and Key Derivation.
__NOTE:__ If the secure channel is going to be opened when no security domain is selected then the command  get_secure_channel_protocol_details must be executed before to be able to get the Secure Channel Protocol Implementation.

__select__ -AID *AID*

:    Select AID instance

__install__ -file *appletFile* -priv *privilege* -sdAID *sdAID* -AID *AIDInPkg* -pkgAID *packageAID* -instAID *instanceAID* -nvCodeLimit *x* -nvDataLimit *y* -instParam *installationParams* -uiccSystemSpecParam *uiccSystemSpecParams*

:    Load and installs an applet in one step

The parameters -AID -instAID -pkgAID -nvCodeLimit can be detected automatically and the -AID and -instAID is set to the first applet in *appletfile*.

For the *sdAID* the AID selected with the select command is chosen if not given. Otherwise the default Card Manager / Security Issuer Domain AID is chosen. Usually you do not have to pass it.

-instParam specifies applet installation parameters for the install() method
-uiccSystemSpecParam specifies parameters according to ETSI TS 102 226, sect. 8.2.1.3.2.2. to use the Card Application Toolkit (CAT) functionality or to access the UICC file system. The parameters have to be already encoded without the outer tag 'EA'.

__install_for_load__ -pkgAID *packageAID* -sdAID *sdAID* -nvCodeLimit *y*

:    Applet load preparation

For the *sdAID* the AID selected with the select command is chosen if not given. Otherwise the default Card Manager / Security Issuer Domain AID is chosen. Usually you do not have to pass it.

This command may be needed if the combined install command does not work.

__load__ -file *appletFile*

:    Load applet

This command may be needed if the combined install command does not work.

__install_for_install__ -priv *privilege* -AID *AIDInPkg* -pkgAID *pkgAID* -instAID *instanceAID* -nvDataLimit *x* -instParam *installationParams* -uiccSystemSpecParam *uiccSystemSpecParams*

:     Instantiate applet

This command may be needed if the combined install command does not work. Or you want to install a pre-installed Security Domain.

__install_for_make_selectable__ -priv *privilege* -instAID *instanceAID*

:     Makes an installed applet instance selectable

This command may be needed if the combined install command does not work. Typically this is used after an *install_for_install*
followed by personalization.

__card_disconnect__

:    Disconnect card

__get_status__ -element *e0*

:     List applets and packages and security domains

__get_status__ -element *20*

:    List packages

__get_status__ -element *40*

:     List applets or security domains

__get_status__ -element *80*

:    List Card Manager / Security Issuer Domain

__release_context__

:    Release context

__put_sc_key__ -keyver *keyver* -newkeyver *newkeyver* -mac_key *new_MAC_key* -enc_key *new_ENC_key* -kek_key *new_KEK_key*

:    Add or replace a key set version

If a new key set version is to be added *keyver* must be set to 0.
If *keyver* equals *newkeyver* an existing key version is replaced.
An existing key set version cannot be replaced with a key set version using a different key size.

__put_sc_key__ -keyver *keyver* -newkeyver *newkeyver* -key *key* -keyDerivation "derivation"

:    Replace key set version *keyver* using key derivation *derivation* using the master (mother) key *y*

__put_dm_keys__ -keyver *keyver* -newkeyver *newkeyver* -file *public_rsa_key_file* -pass *password* -key *new_receipt_generation_key*

:     Add a RSA delegated management key in version *newkeyver*

__send_apdu__ -sc 0 -APDU *apdu*

:    Send APDU *apdu* without secure channel

The APDU is given as hex without spaces and without leading 0x.

__get_data__ -identifier *identifier*

:    A GET DATA command returning the data for the given identifier. See the identifier options for details.

__get_key_information_templates__ -keyTemplate *index*

:    A GET DATA command returning the key information templates in the selected security domain. __NOTE:__ The security domain must be selected and this only works outside of a secure channel.

__get_extended_card_resources_information__

:     A GET DATA command returning the extended card resources information in the issuer security domain. __NOTE:__ The security domain must be selected and this only works outside of a secure channel.

__get_secure_channel_protocol_details__

:     A GET DATA command returning the secure channel protocol details and remembering them for a later open_sc. __NOTE:__ The security domain must be selected and this only works outside of a secure channel.

__print__ <text to print>

:     Prints a line of text.  Prints an empty line if no text is given.

__install_for_personalization__ -aid *AID*

:     Prepare a security domain for the personalization of an applet with following store_data commands. __NOTE:__ The security domain must be selected and this only works outside of a secure channel.

__store_data__ -dataFormat *format* -dataEncryption *encryption* -data *data*

:     Executes a STORE DATA command passing the *data* to the selected applet.

__get_card_recognition_data__

:     A GET DATA command returning the card recognition data. __NOTE:__ The security domain must be selected.

__delete_key__ -keyver *keyver* -keyind *keyind*

:     Deletes a key set version with a DELETE command.
If only the keyver is passed the complete key set version is deleted.
By default keyind is 0xFF to delete the complete key set version. If keyver is 0 all key set with the passed keyind are deleted.

# OPTIONS

__-keyind__ *x*

:    Key index *x*

__-keyver__ *x*
Key set version x

__-newkeyver__ *x*

:    New key set version x

__-key__ *key*

:    Key value in hex

__-mac_key__ *key*

:    MAC key value in hex

__-enc_key__ *key*

:    ENC key value in hex

__-kek_key__ *key*

:    KEK key value in hex

__-security__ *x*

:    0: clear, 1: MAC, 3: MAC+ENC, 51: MAC+ENC+R-MAC+E-ENC (SCP03 only), 19: MAC+ENC-R-MAC (SCP02+SCP03 only), 17: MAC+R-MAC (SCP02+SCP03 only)

__-reader__ *readerName*

:    Smart card reader name

__-readerNumber__ *x*

:    Number of the reader in the system to connect to. If -reader is given this is ignored.

__-protocol__ *x*

:    Protocol, 0:T=0, 1:T=1 Should not be necessary to be stated explicitly.

__-AID__ *aid*

:    Applet ID

__-sdAID__ *aid*

:    Security Domain AID

__-pkgAID__ *aid*

:    Package AID

__-instAID__ *aid*

:    Instance AID

__-nvCodeLimit__ *x*

:    Non-volatile code size limit

__-nvDataLimit__ *x*

:    Non-volatile data size limit

__-vDataLimit__ *x*

:    Volatile data size limit

__-file__ *name*

:    File name

__-instParam__ *param*

:    Installation parameter

__-uiccSystemSpecParam__ *param*

:    UICC System Specific Parameters according to ETSI TS 102 226, sect. 8.2.1.3.2.2.

__-element__ *x*

:    Element type to be listed in hex

* 80 - Card Manager / Card Issuer Security Domain only.
* 40 - Applications (and Security Domains only in GP211 and later).
* 20 - Executable Load Files only.
* 10 - Executable Load Files and their Executable Modules only (Only GP211 and later)

__-format__ *x*

:    Sets the format of the response of the get_status command. This is only used for GlobalPlatform cards and required and only needed if the default is not supported by the smart card.

__-dataFormat__ *x*

:    Sets the data format flag for store_data command. Default 0.

* 0 - No general encryption information or non - encrypted data
* 0x20 - Application dependent encryption of the data
* 0x40 - RFU(encryption indicator)
* 0x60 - Encrypted data. Must be encrypted with data encryption key.

__-dataEncryption__ *x*

:    Sets the encryption format flag for store_data command. Note that this is just a flag and the data must be passed already in the correct encryption. Default 0.

* 0 - No general data structure information
* 0x08 - DGI format of the command data field
* 0x10 - BER-TLV format of the command data field
* 0x18 - RFU (data structure information)

__-responseDataExpected__ *x*

:    Sets if response data is expected for store_data command. 1 for expecting response data. Default 0.

__-keyTemplate__ *x*

:    Sets the key template index to return for the get_key_templates command. Default 0.

* 0 - Deprecated format
* 2 - New format (default)

__-sc__ *x*

:    Secure Channel mode (0 off, 1 on)

__-APDU__ *apdu*

:    APDU to be sent. Must be in hex format, e.g. 80CA00CF00.

__-priv__ *x*

:    Privilege. E.g. 0x04 Default Selected

__-scp__ *x*

:    Secure Channel Protocol (1 SCP01, 2 SCP02, 3 SCP03, default no set). Should not be necessary to be stated explicitly.

__-scpimpl__ *x*

:    Secure Channel Implementation (default not set)
Should not be necessary to be stated explicitly. See the get_secure_channel_protocol_details command to detect the Secure Channel Protocol Implementation.
__NOTE:__ The value can be passed as decimal value or hexadecimal prefixed by "0x". The hexadecimal version is the common one.

__-pass__ *password*

:    Password for key decryption

__-identifier__ *identifier*

:    Identifier for the tag for the get_data command. Must be in hex format, e.g. 9F7F.

There are several identifiers available but in general not all cards are supporting them. The GlobalPlatform specification v2.3.1 lists a few in section 11.3.3.1.
It is useful to use some ASN.1 parser to interpret these data, like [asn1js](https://lapo.it/asn1js)

Some useful identifier are:

* 9F7F - CPLC (Card Production Life Cycle) Data
* 00E0 - Key Information Templates. Instead of the first byte 00 also 01, ... can be used to get more key information templates if available. There is a dedicated command for getting this: get_key_information_templates
* 2F00 - List of applications
* FF21 - Extended card resources. There is a dedicated command for getting this: get_extended_card_resources_information
* 0066 - Card Recogniti0on Data. There is a dedicated command for getting this: get_card_recognition_data

__-data__ *data*

:    Data in hex format for the store_data command.

__-noStop__

:    Does not stop in case of an error

## Format of CPLC data

You see the command trace of a GET DATA command and the interpreted result.

~~~
=> 80 CA 9F 7F 00 .....
(12102 usec)
<= 9F 7F 2A 47 90 50 40 47 91 81 02 31 00 83 58 00 ..*G.P@G...1..X.
11 68 91 45 81 48 12 83 65 00 00 00 00 01 2F 31 .h.E.H..e...../1
30 31 31 36 38 00 00 00 00 00 00 00 00 90 00 01168..........
Status: No Error
IC Fabricator : 4790
IC Type : 5040
Operating System ID : 4791
Operating System release date : 8102 (11.4.2008)
Operating System release level : 3100
IC Fabrication Date : 8358 (23.12.2008)
IC Serial Number : 00116891
IC Batch Identifier : 4581
IC Module Fabricator : 4812
IC Module Packaging Date : 8365 (30.12.2008)
ICC Manufacturer : 0000
IC Embedding Date : 0000
IC Pre-Personalizer : 012F
IC Pre-Perso. Equipment Date : 3130 (10.5.2003)
IC Pre-Perso. Equipment ID : 31313638
IC Personalizer : 0000
IC Personalization Date : 0000
IC Perso. Equipment ID : 00000000
~~~
Dates are stored as 2 bytes, the first specifying the year in the decade and the last 3 bytes the day within the year.

__-keyDerivation__ *derivation method*

:    Possible values are *none*, *visa2* or *emvcps11*

Choose *visa2* if you have a card which uses the VISA key derivation scheme for the key calculation, like GemXpresso Pro or some JCOP cards you must set this.

Choose *emvcps11* If you have a card which uses the EMV CPS 1.1 key derivation scheme for the key calculation, like a Sm@rtCafe Expert 3.0 and later you must set this.
Also for put_sc_key this is necessary for Sm@rtcafe 5.0 (and earlier(?)) cards

# ENVIRONMENT

__GLOBALPLATFORM_DEBUG__

:    Enables debugging output from the underlying GlobalPlatform library.

__GLOBALPLATFORM_LOGFILE__

:    Sets the log file name for the debugging output.

# Key Derivation

__visa2__

:     For the VISA2 key derivation scheme, like used in a GemXpresso Pro or some JCOP cards.

__emvcps11__

:    For the key derivation according to EMV CPS 1.1 (CDK (CPG 2.04)), like Sm@rtCafe Expert 3.0 and later.

Known unsupported key derivation schemes are:

* CDK (CPG 2.02)
* ISK(D)

# Supported Cards

* Gemalto IDCore 3010
* Oberthur CosmopoliC 32K (OP201)
* CosmopoliC 64K V5.2 (GP211, SCP01, Impl05)
* Axalto Cyberflex e-gate 32k (OP201)
* GemXpresso R3.2 E64
* IBM JCOP v2.2 41 (GP211)
* IBM JCOP 31 (36k)
* Palmera Protect V5
* JTopV15
* Nokia 6131 NFC Phone (GP211)
* Axalto Cyberflex Access 64k
* Gemalto Generations Flexible
* Sm@rtCafe Expert 3.0
* Tongfang420
* Infineon SECORA™ ID S
* JCOP4 P71
* JCPO3 P60 EMV
* JCOP3 P60 SecID CS
* JCOP3 P40 EMV
* JCOP3 P40 SecID
* JCOP2.4.x

# Misc

## About install_for_load and install

For CosmopoliC 64K (tested on V5.2), you need to specify the Security Domain AID. For example,

    install -file helloworld.cap -sdAID A000000003000000 -nvCodeLimit 4000

For GemXpresso R3.2 E64, you need to specify the Security Domain AID (Card Manager AID). For example,

    install -file helloworld.cap -sdAID A000000018434D00 -nvCodeLimit 4000

## JCOP cards

If you cannot authenticate to your card it might be not fused. In this case you need the transport key from the vendor.
Execute the JCOP IDENTIFY command.

select -aid A000000167413000FF
Offset 14 (decimal) of the response has the pre-personalized state. 00h means not fused (not personalized), 01h means fused.

## CyberFlex cards

For the Cyberflex you also need the CAP transformer (I believe this is
a kind of obfuscator) which you must apply to the CAP file. Download it
from http://www.trusted-logic.fr/down.php and use it.

# BUGS

JCOP 10

:    install_for_load fails for unknown reason, so nothing can be installed.

Some cards are not supporting the GET DATA command. This command is used by GPShell for retrieving the secure channel parameters. So you have to pass -scp 2 -scpimpl 0x15 to open_sc command.

# AUTHOR

Karsten Ohme *k_o_@users.sourceforge.net*
Snit Mo *snitmo@gmail.com*

See the file `AUTHORS` for a complete list.
