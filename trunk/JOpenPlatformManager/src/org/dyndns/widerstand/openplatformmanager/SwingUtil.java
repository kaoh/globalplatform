/*
 * swingUtil.java
 *
 * Created on 17. Februar 2005, 06:45
 */

package org.dyndns.widerstand.openplatformmanager;

import javax.swing.JComponent;
import java.awt.Color;
import java.awt.Component;
import javax.swing.*;

/**
 *
 * @author Widerstand
 */
public class SwingUtil {
    
    /**
     * Holds value of property failureColor.
     */
    private Color failureColor = Color.orange;
    
    /**
     * Holds value of property originalColor.
     */
    private java.awt.Color originalColor;
    
    /**
     * The actual watched JComponent.
     */
    private JComponent component;
    
    /** Creates a new instance of swingUtil */
    public SwingUtil() {
    }
    
    public void errorInJComponent(Component parent, JComponent component, String errorString, String title) {
        originalColor = component.getBackground();
        this.component = component;
        javax.swing.JOptionPane.showMessageDialog(parent, errorString, title, javax.swing.JOptionPane.ERROR_MESSAGE);
        component.setBackground(failureColor);
        component.requestFocus();
        return;
    }
    
    public void resetJComponentColor() {
        if (component != null) {
            component.setBackground(originalColor);
        }
    }
    
    /**
     * Getter for property failureColor.
     * @return Value of property failureColor.
     */
    public Color getFailureColor() {
        return failureColor;
    }
    
    /**
     * Setter for property failureColor.
     * @param failureColor New value of property failureColor.
     */
    public void setFailureColor(Color failureColor) {
        failureColor = failureColor;
    }
    
    /**
     * Getter for property originalColor.
     * @return Value of property originalColor.
     */
    public java.awt.Color getOriginalColor() {
        
        return originalColor;
    }
    
    /**
     * Setter for property originalColor.
     * @param originalColor New value of property originalColor.
     */
    public void setOriginalColor(java.awt.Color originalColor) {
        originalColor = originalColor;
    }
    
}
