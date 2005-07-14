/*
 * SessionInformation.java
 *
 * Created on 19. Februar 2005, 22:58
 */

package org.dyndns.widerstand.openplatformmanager;

import java.util.*;
import org.dyndns.widerstand.OpenPlatform.*;

/**
 *
 * @author Widerstand
 */
public class SessionInformation {
    
    public long cardContext = 0;
    public long cardHandle = 0;
    public Vector<String> readers = new Vector<String>(2);
    OPSPCardConnectionInfo cardInfo;
    OPSPSecurityInfo secInfo;
    public ArrayList<OPSPApplicationData> loadFiles = new ArrayList<OPSPApplicationData>(10);
    public ArrayList<OPSPApplicationData> cardManager = new ArrayList<OPSPApplicationData>(1);
    public ArrayList<OPSPApplicationData> securityDomains = new ArrayList<OPSPApplicationData>(3);
    public ArrayList<OPSPApplicationData> applications = new ArrayList<OPSPApplicationData>(5);
    public byte[] kekKey;
    
    /** Creates a new instance of SessionInformation */
    public SessionInformation() {
    }
    
}
