/*
 * OPSPJTree.java
 *
 * Created on 18. Februar 2005, 03:41
 */

package org.dyndns.widerstand.openplatformmanager;

import org.dyndns.widerstand.OpenPlatform.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.tree.*;
import java.util.*;
import java.awt.Component;

/**
 *
 * @author Widerstand
 */
public class OPSPJTree extends JTree implements MouseListener {
    
    private HashMap<DefaultMutableTreeNode, JPopupMenu> map;
    private static DefaultMutableTreeNode root = new DefaultMutableTreeNode("Context");
    private SessionInformation session;
    private MainJFrame main;
    
    private static final String Establish_Context = "Establish Context";
    private static final String Release_Context = "Release Context";
    private static final String Open_Platform_Error = "Open Platform Error";
    private static final String Connect_to_reader = "Connect to reader";
    private static final String Disconnect_from_reader = "Disconnect from reader";
    
    OPSPJTree(SessionInformation session, MainJFrame main) {
        super(root);
        this.session = session;
        this.main = main;
        map = new HashMap<DefaultMutableTreeNode, JPopupMenu>();
        JPopupMenu popup;
        JMenuItem mi;
        popup = new JPopupMenu();
        mi = new JMenuItem(Establish_Context);
        mi.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                establishContext(evt);
            }
        });
        popup.add(mi);
        mi = new JMenuItem(Release_Context);
        mi.setEnabled(false);
        mi.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                releaseContext(evt);
            }
        });
        popup.add(mi);
        popup.setOpaque(true);
        popup.setLightWeightPopupEnabled(true);
        map.put(root, popup);
        this.addMouseListener(this);
    }
    
    private void establishContext(ActionEvent ae) {
        String[] readers;
        try {
            session.cardContext = OPSPWrapper.establishContext();
            readers = OPSPWrapper.listReaders(session.cardContext);
        } catch (OPSPException e) {
            javax.swing.JOptionPane.showMessageDialog(this, e.getMessage(),
                    Open_Platform_Error, javax.swing.JOptionPane.ERROR_MESSAGE);
            return;
        }
        DefaultMutableTreeNode dmtn, node;
        JPopupMenu popup;
        dmtn = getTreeNode();
        for (int i=0; i<readers.length; i++) {
            node = new DefaultMutableTreeNode(readers[i]);
            final int j=i;
            dmtn.add(node);
            JMenuItem mi;
            popup = new JPopupMenu();
            mi = new JMenuItem(Connect_to_reader);
            mi.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent evt) {
                    cardConnect(evt, j);
                }
            });
            popup.add(mi);
            mi = new JMenuItem(Disconnect_from_reader);
            mi.setEnabled(false);
            mi.addActionListener(new java.awt.event.ActionListener() {
                public void actionPerformed(java.awt.event.ActionEvent evt) {
                    cardDisconnect(evt, j);
                }
            });
            popup.setOpaque(true);
            popup.setLightWeightPopupEnabled(true);
            
            map.put(node, popup);
        }
        getJMenuItem(getJPopupMenu(), Release_Context).setEnabled(true);
        getJMenuItem(getJPopupMenu(), Establish_Context).setEnabled(false);
        ((DefaultTreeModel )this.getModel()).nodeStructureChanged((TreeNode)dmtn);
    }
    
    private JMenuItem getJMenuItem(JPopupMenu menu, String id) {
        Component component;
        for (int i=0; i<menu.getComponentCount(); i++) {
            component = menu.getComponent(i);
            if (component instanceof JMenuItem) {
                if (((JMenuItem)component).getText().equals(id))
                    return (JMenuItem)component;
            }
        }
        return null;
    }
    
    private void releaseContext(ActionEvent ae) {
        try {
            OPSPWrapper.releaseContext(session.cardContext);
        } catch (OPSPException e) {
            javax.swing.JOptionPane.showMessageDialog(this, e.getMessage(),
                    Open_Platform_Error, javax.swing.JOptionPane.ERROR_MESSAGE);
            return;
        }
        DefaultMutableTreeNode dmtn = getTreeNode();
        for (int i=0; i<dmtn.getChildCount(); i++) {
            map.remove(dmtn.getChildAt(i));
        }
        dmtn.removeAllChildren();
        getJMenuItem(getJPopupMenu(), Release_Context).setEnabled(false);
        getJMenuItem(getJPopupMenu(), Establish_Context).setEnabled(true);
        ((DefaultTreeModel )this.getModel()).nodeStructureChanged((TreeNode)dmtn);
    }
    
    private void cardConnect(ActionEvent evt, int reader) {
//        main.setRightComponent(new ConnectJPanel(session, main));
    }
    
    private void cardDisconnect(ActionEvent evt, int reader) {
        
    }
    
    public void mouseClicked(MouseEvent mouseEvent) {
    }
    
    public void mouseEntered(MouseEvent mouseEvent) {
    }
    
    public void mouseExited(MouseEvent mouseEvent) {
    }
    
    public void mousePressed(MouseEvent mouseEvent) {
    }
    
    private DefaultMutableTreeNode getTreeNode() {
        TreePath path = this.getSelectionPath();
        if (path == null) return null;
        DefaultMutableTreeNode dmtn = (DefaultMutableTreeNode) path.getLastPathComponent();
        for(DefaultMutableTreeNode key : map.keySet()) {
            if (key == dmtn) return key;
        }
        return null;
    }
    
    private JPopupMenu getJPopupMenu() {
        TreePath path = this.getSelectionPath();
        if (path == null) return null;
        DefaultMutableTreeNode dmtn = (DefaultMutableTreeNode) path.getLastPathComponent();
        for(DefaultMutableTreeNode key : map.keySet()) {
            if (key == dmtn) return map.get(key);
        }
        return null;
    }
    
    public void mouseReleased(MouseEvent mouseEvent) {
        if (mouseEvent.isPopupTrigger()) {
            JPopupMenu menu = getJPopupMenu();
            if (menu != null)
                menu.show( (JComponent)mouseEvent.getSource(), mouseEvent.getX(), mouseEvent.getY() );
        }
    }
}
