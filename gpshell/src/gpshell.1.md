% GPSHELL(1) 1.4.5 | GPShell Documentation

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

# COMMANDS

-mode_201

:    Set protocol mode to OpenPlatform 2.0.1. This is the default.

-mode_211

:    Set protocol mode to GlobalPlatform 2.1.1 and later

-visa_key_derivation

:   For cards which use the VISA key derivation scheme for the key calculation, like GemXpresso Pro, Palmera Protect or some JCOP cards this must be set.

-emv_cps11_key_derivation

:    For cards which uses the EMV CPS 1.1 key derivation scheme for the key calculation, like a Sm@rtCafe Expert 3.0 this must be set.

-enable_trace

:    Enable APDU trace

You will see the sent APDUs in clear text. The last two bytes of the response are the response code. A response code of 9000 means success, otherwise the response code indicates an error. This may be OK when deleting a non existing applet or package.

-enable_timer

:    Enable the logging of the execution times of commands.

-establish_context

:    Establish context. This must always be executed before connecting to a card.

-card_connect -reader *readerName*

:    Connect to card in the reader with *readerName*

-card_connect -readerNumber *x*

:    Connect to card in the *x* th reader in the system

-open_sc -keyind *x* -keyver *x* -key *key* -mac_key *mac-key* -enc_key *enc-key* -kek_key *kek-key* -security *securityLevel* -scp *protocol* -scpimpl *impl* -keyDerivation *derivation*

:    Open a secure channel

For OpenPlatform 2.0.1' cards only -keyind -keyver -mac_key and -enc_key are necessary.

For GlobalPlatform 2.1.1 and later cards -scp and -scpimpl should not be necessary to supply. You must also specify -kek_key.

If the card supports a Secure Channel Protocol Implementation with only one base key, specify this key with -key and omit the others.

If the card uses a key derivation mechanism you must enable the derivation mode with the -keyDerivation option and you must specify with -key the master (mother) key. -kek_key, -mac_key and -enc_key are not relevant is this case. See the section Options and Key Derivation.

-select -AID *AID*

:    Select AID instance

-install -file *appletFile* -priv *privilege* -sdAID *sdAID* -AID *AIDInPkg* -pkgAID *packageAID* -instAID *instanceAID* -nvCodeLimit *x* -nvDataLimit *y*

:    Load and installs in one step

The parameters -AID -instAID -pkgAID -nvCodeLimit can be detected automatically and the -AID and -instAID is set to the first applet in *appletfile*.

For the *sdAID* the AID selected with the select command is chosen if not given. Otherwise the default Card Manager / Security Issuer Domain AID is chosen. Usually you do not have to pass it.

-install_for_load -pkgAID *packageAID* -sdAID *sdAID* -nvCodeLimit *y*

:    Install for Load

For the *sdAID* the AID selected with the select command is chosen if not given. Otherwise the default Card Manager / Security Issuer Domain AID is chosen. Usually you do not have to pass it.

This command may be needed if the combined install command does not work.

-load -file *appletFile*

:    Load applet

This command may be needed if the combined install command does not work.

-install_for_install -priv *privilege* -AID *AIDInPkg* -pkgAID *pkgAID* -instAID *instanceAID* -nvDataLimit *x*

:     Instantiate applet

This command may be needed if the combined install command does not work. Or you want to install a pre-installed Security Domain.

-card_disconnect

:    Disconnect card

-get_status -element *e0*

:     List applets and packages and security domains

-get_status -element *20*

:    List packages

-get_status -element *40*

:     List applets or security domains

-get_status -element *80*

:    List Card Manager / Security Issuer Domain

-release_context

:    Release context

-put_sc_key -keyver *keyver* -newkeyver *newkeyver* -mac_key *new_MAC_key* -enc_key *new_ENC_key* -kek_key *new_KEK_key*

:    Add or replace a key set version

If a new key set version is to be added *keyver* must be set to 0.
If *keyver* equals *newkeyver* an existing key version is replaced.

-put_sc_key -keyver *keyver* -newkeyver *newkeyver* -key *key* -keyDerivation "derivation"

:    Replace key set version *keyver* using key derivation *derivation* using the master (mother) key *y*

-put_dm_keys -keyver *keyver* -newkeyver *newkeyver* -file *public_rsa_key_file* -pass *password* -key *new_receipt_generation_key*

:     Add a RSA delegated management key in version *newkeyver*

-send_apdu -sc 0 -APDU *apdu*

:    Send APDU *apdu* without secure channel

The APDU is given as hex without spaces and without leadings 0x.

-send_apdu_nostop -sc 0 -APDU *apdu*

:    Does not stop in case of an error

The APDU is given as hex without spaces and without leadings 0x.

-get_data -identifier *identifier*

:    A GET DATA command returning the data for the given identifier. See the identifier options for details.

-get_key_information_templates -keyTemplate *index*

:    A GET DATA command returning the key information templates in the selected security domain.

-get_extended_card_resources_information

:     A GET DATA command returning the extended card resources information in the issuer security domain.

# OPTIONS

--keyind *x*

:    Key index *x*

--keyver *x*
Key set version x

--newkeyver *x*

:    New key set version x

--key *key*

:    Key value in hex

--mac_key *key*

:    MAC key value in hex

--enc_key *key*

:    ENC key value in hex

--kek_key *key*

:    KEK key value in hex

--security *x*

:    0: clear, 1: MAC, 3: MAC+ENC, 51: MAC+ENC+R-MAC+E-ENC (SCP03 only), 19: MAC+ENC-R-MAC (SCP02+SCP03 only), 17: MAC+R-MAC (SCP02+SCP03 only)

--reader *readerName*

:    Smart card reader name

--readerNumber *x*

:    Number of the reader in the system to connect to. If -reader is given this is ignored.

--protocol *x*

:    Protocol, 0:T=0, 1:T=1 Should not be necessary to be stated explicitly.

--AID *aid*

:    Applet ID

--sdAID *aid*

:    Security Domain AID

--pkgAID *aid*

:    Package AID

--instAID *aid*

:    Instance AID

--nvCodeLimit *x*

:    Non-volatile code size limit

--nvDataLimit *x*

:    Non-volatile data size limit

--vDataLimit *x*

:    Volatile data size limit

--file *name*

:    File name

--instParam *param*

:    Installation parameter

--element *x*

:    Element type to be listed in hex

* 80 - Card Manager / Card Issuer Security Domain only.
* 40 - Applications (and Security Domains only in GP211 and later).
* 20 - Executable Load Files only.
* 10 - Executable Load Files and their Executable Modules only (Only GP211 and later)

--format *x*

:    Sets the format of the response of the get_status command. This is only used for GlobalPlatform cards and required and only needed if the default is not supported by the smart card.

--keyTemplate *x*

:    Sets the key template index to return for the get_key_templates command. Default 0.

* 0 - Deprecated format
* 2 - New format (default)

--sc *x*

:    Secure Channel mode (0 off, 1 on)

--APDU *apdu*

:    APDU to be sent. Must be in hex format, e.g. 80CA00CF00.

--priv *x*

:    Privilege. E.g. 0x04 Default Selected

--scp *x*

:    Secure Channel Protocol (1 SCP01, 2 SCP02, 3 SCP03, default no set). Should not be necessary to be stated explicitly.

--scpimpl *x*

:    Secure Channel Implementation (default not set)
Should not be necessary to be stated explicitly.

--pass *password*

:    Password for key decryption

--identifier *identifier*

:    Identifier for the tag for the get_data command. Must be in hex format, e.g. 9F7F.

There are several identifiers available but in general not all cards are supporting them. The GlobalPlatform specification v2.3.1 lists a few in section 11.3.3.1.
It is useful to use some ASN.1 parser to interpret these data, like [asn1js](https://lapo.it/asn1js)

Some useful identifier are:

* 9F7F - CPLC (Card Production Life Cycle) Data
* 00E0 - Key Information Templates. Instead of the first byte 00 also 01, ... can be used to get more key information templates if available. There is a dedicated command for getting this: get_key_information_templates
* 2F00 - List of applications
* FF21 - Extended card resources. There is a dedicated command for getting this: get_extended_card_resources_information

--keyDerivation *derivation method*

:    Possible values are *none*, *visa2* or *emvcps11*

Choose *visa2* if you have a card which uses the VISA key derivation scheme for the key calculation, like GemXpresso Pro or some JCOP cards you must set this.

Choose *emvcps11* If you have a card which uses the EMV CPS 1.1 key derivation scheme for the key calculation, like a Sm@rtCafe Expert 3.0 and later you must set this.
Also for put_sc_key this is necessary for Sm@rtcafe 5.0 (and earlier(?)) cards

# ENVIRONMENT

-GLOBALPLATFORM_DEBUG

:    Enables debugging output from the underlying GlobalPlatform library.

-GLOBALPLATFORM_LOGFILE

:    Sets the log file name for the debugging output.

# Key Derivation

-visa2

:     For the VISA2 key derivation scheme, like used in a GemXpresso Pro or some JCOP cards.

-emvcps11

:    For the key derivation according to EMV CPS 1.1 (CDK (CPG 2.04)), like Sm@rtCafe Expert 3.0 and later.

Known unsupported key derivation schemes are:

* CDK (CPG 2.02)
* ISK(D)

# BUGS

JCOP 10

:    install_for_load fails for unknown reason, so nothing can be installed.

# AUTHOR

Karsten Ohme *k_o_@users.sourceforge.net*
Snit Mo *snitmo@gmail.com*

See the file `AUTHORS` for a complete list.
