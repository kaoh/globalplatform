/*
 * FileItem.java
 *
 * Created on 2. März 2005, 13:41
 */

package org.dyndns.widerstand.openplatformmanager;

/**
 *
 * @author Widerstand
 */
public class FileItem {
    
    private String fullName;
    private String lastName;
    
    public FileItem(String lastName, String fullName) {
        this.lastName = lastName;
        this.fullName = fullName;
    }
    
    public String toString() {
        return lastName;
    }
    
    public String fullName() {
        return fullName;
    }
}
