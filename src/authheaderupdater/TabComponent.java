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
    final private JCheckBox enabled;
    final private JTextArea authToken;
    final private JLabel headerLabel;
    final private JLabel tokenLabel;

    public TabComponent(IBurpExtenderCallbacks callbacks, BurpExtender extender)
    {
        this.callbacks = callbacks;
        this.extender = extender;

        this.headerLabel = new JLabel();
        this.enabled = new JCheckBox();
        this.authToken = new JTextArea(5,40);
        this.tokenLabel = new JLabel();
        
        initComponents();

        this.callbacks.customizeUiComponent(this.enabled);
        this.callbacks.customizeUiComponent(this.authToken);
        this.callbacks.customizeUiComponent(this.headerLabel);
        this.callbacks.customizeUiComponent(this.tokenLabel);
    }

    
    private void initComponents()
    {        
        this.headerLabel.setFont(new Font("Tahoma", 1, 16));
        this.headerLabel.setForeground(new Color(229, 137, 0));
        this.headerLabel.setText("Auth Header Settings");
        this.headerLabel.setAlignmentX(CENTER_ALIGNMENT);
        
        this.enabled.setSelected(false);
        this.enabled.setText("Enabled");
        this.enabled.setAlignmentX(CENTER_ALIGNMENT);

        this.tokenLabel.setFont(new Font("Tahoma", 1, 13));
        this.tokenLabel.setForeground(new Color(229, 137, 0));
        this.tokenLabel.setText("Auth Bearer Token: ");
        this.tokenLabel.setAlignmentX(LEFT_ALIGNMENT);
        
        authToken.setLineWrap(true);
        
        JPanel tokenPanel = new JPanel(new FlowLayout());
        tokenPanel.add(tokenLabel);
        tokenPanel.add(authToken);
        
        JPanel panel = new JPanel();
        BoxLayout boxlayout = new BoxLayout(panel, BoxLayout.Y_AXIS);
        panel.setLayout(boxlayout);

        //Add the items
        panel.add(this.headerLabel);
        panel.add(new JLabel("  ")); 
        panel.add(tokenPanel);
        panel.add(new JLabel("  ")); 
        panel.add(this.enabled);
        this.add(panel);

    }
    
    @Override
    public boolean isEnabled()
    {
        return enabled.isSelected();
    }
    
    public String getToken()
    {
        return authToken.getText();
    }
}