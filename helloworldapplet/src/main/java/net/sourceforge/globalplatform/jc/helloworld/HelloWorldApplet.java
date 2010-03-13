/**
 *  Copyright (c) 2010 Karsten Ohme
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
package net.sourceforge.globalplatform.jc.helloworld;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 */

public class HelloWorldApplet extends Applet {
    private byte[] echoBytes;
    private static final short LENGTH_ECHO_BYTES = 256;

    /**
     * Only this class's install method should create the applet object.
     */
    protected HelloWorldApplet() {
        echoBytes = new byte[LENGTH_ECHO_BYTES];
        register();
    }

    /**
     * Installs this applet.
     *
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HelloWorldApplet();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu
     *            the incoming APDU
     * @exception ISOException
     *                with the response bytes per ISO 7816-4
     */
    public void process(APDU apdu) {
        byte buffer[] = apdu.getBuffer();

        short bytesRead = apdu.setIncomingAndReceive();
        short echoOffset = (short) 0;

        while (bytesRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, echoBytes, echoOffset, bytesRead);
            echoOffset += bytesRead;
            bytesRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (echoOffset + 5));

        // echo header
        apdu.sendBytes((short) 0, (short) 5);
        // echo data
        apdu.sendBytesLong(echoBytes, (short) 0, echoOffset);
    }
}
//import javacard.framework.APDU;
//import javacard.framework.Applet;
////import javacard.framework.Util;
//
///**
// * Hello World Applet.
// */
//public class HelloWorldApplet extends Applet {
//
////    private final static byte[] HELLO_WORLD = new byte[] {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
//
//    public HelloWorldApplet() {
//        register();
//    }
//
//    /**
//     * Installs the applet.
//     *
//     * @param bArray
//     *            array with installation parameters.
//     * @param bOffset
//     *            offset into array.
//     * @param bLength
//     *            the length of the parameters.
//     */
//    public static void install(byte[] bArray, short bOffset, byte bLength) {
//        new HelloWorldApplet();
//    }
//
//    /**
//     * Processes an incoming APDU.
//     *
//     * @param apdu
//     *            the APDU.
//     */
//    public void process(APDU apdu) {
//        byte buffer[] = apdu.getBuffer();
//        apdu.setIncomingAndReceive();
////        Util.arrayCopyNonAtomic(HELLO_WORLD, (short) 0, buffer, (short)0, (short)HELLO_WORLD.length);
////        apdu.setOutgoingAndSend((short)0, (short)HELLO_WORLD.length);
//    }
//
//}
