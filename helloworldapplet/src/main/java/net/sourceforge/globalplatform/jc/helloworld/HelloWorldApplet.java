/*
 *  Copyright (c) 2010-2026, Karsten Ohme
 *  This file is part of GlobalPlatform.
 *
 *  GlobalPlatform is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GlobalPlatform is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GlobalPlatform.  If not, see <https://www.gnu.org/licenses/>.
 */
package net.sourceforge.globalplatform.jc.helloworld;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.Util;
import javacard.framework.MultiSelectable;


/**
 * Hello World Applet.
 */
public class HelloWorldApplet extends Applet implements MultiSelectable {

    private final static byte[] HELLO_WORLD = new byte[]{'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};

    private HelloWorldApplet() {
        register();
    }

    /**
     * Installs the applet.
     *
     * @param bArray
     *            array with installation parameters.
     * @param bOffset
     *            offset into array.
     * @param bLength
     *            the length of the parameters.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HelloWorldApplet();
    }

    public void deselect(boolean appInstStillSelected) { 
 
    } 

    public boolean select(boolean appInstAlreadySelected) { 
        return true;
    } 
    
    /**
     * Processes an incoming APDU.
     *
     * @param apdu
     *            the APDU.
     */
    public void process(APDU apdu) {
        // When a SELECT command is received (on any channel), simply return.
        if (selectingApplet()) {
            return;
        }
        byte buffer[] = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        Util.arrayCopyNonAtomic(HELLO_WORLD, (short) 0, buffer, (short) 0, (short) HELLO_WORLD.length);
        apdu.setOutgoingAndSend((short) 0, (short) HELLO_WORLD.length);
    }
}
