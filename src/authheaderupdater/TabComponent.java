/*
 * The MIT License
 *
 * Copyright 2018 Carl Sampson <chs@chs.us>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package authheaderupdater;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.*;

public class TabComponent extends JPanel
{

    IBurpExtenderCallbacks callbacks;
    BurpExtender extender;
    final private JCheckBox jCheckBoxEnabled;
    final private JTextArea jAuthToken;
    final private JLabel jLabelHeader;
    final private JLabel jLabelToken;

    public TabComponent(IBurpExtenderCallbacks callbacks, BurpExtender extender)
    {
        this.callbacks = callbacks;
        this.extender = extender;

        this.jLabelHeader = new JLabel();
        this.jCheckBoxEnabled = new JCheckBox();
        this.jAuthToken = new JTextArea(5,40);
        this.jLabelToken = new JLabel();
        
        initComponents();

        this.callbacks.customizeUiComponent(this.jCheckBoxEnabled);
        this.callbacks.customizeUiComponent(this.jAuthToken);
        this.callbacks.customizeUiComponent(this.jLabelHeader);
        this.callbacks.customizeUiComponent(this.jLabelToken);
    }

    
    private void initComponents()
    {        
        this.jLabelHeader.setFont(new Font("Tahoma", 1, 16));
        this.jLabelHeader.setForeground(new Color(229, 137, 0));
        this.jLabelHeader.setText("Auth Header Settings");
        this.jLabelHeader.setAlignmentX(CENTER_ALIGNMENT);
        
        this.jCheckBoxEnabled.setSelected(false);
        this.jCheckBoxEnabled.setText("Enabled");
        this.jCheckBoxEnabled.setAlignmentX(CENTER_ALIGNMENT);

        jLabelToken.setFont(new Font("Tahoma", 1, 13));
        jLabelToken.setForeground(new Color(229, 137, 0));
        jLabelToken.setText("Auth Bearer Token: ");
        jLabelToken.setAlignmentX(LEFT_ALIGNMENT);
        
        jAuthToken.setLineWrap(true);
        
        JPanel tokenPanel = new JPanel(new FlowLayout());
        tokenPanel.add(jLabelToken);
        tokenPanel.add(jAuthToken);
        
        JPanel panel = new JPanel();
        BoxLayout boxlayout = new BoxLayout(panel, BoxLayout.Y_AXIS);
        panel.setLayout(boxlayout);

        
        //Add the items
        panel.add(this.jLabelHeader);
        panel.add(new JLabel("  ")); 
        panel.add(tokenPanel);
        panel.add(new JLabel("  ")); 
        panel.add(this.jCheckBoxEnabled);
        this.add(panel);

    }
    
    @Override
    public boolean isEnabled()
    {
        return jCheckBoxEnabled.isSelected();
    }
    
    public String getToken()
    {
        return jAuthToken.getText();
    }
}