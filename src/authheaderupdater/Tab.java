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

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import java.awt.Component;
import javax.swing.JPanel;

public class Tab extends JPanel implements ITab
{
  IBurpExtenderCallbacks mCallbacks;
  String tabName;
  JPanel userDefinedPanel;
  
  public Tab(String tabName, IBurpExtenderCallbacks callbacks)
  {
    this.tabName = tabName;
    this.mCallbacks = callbacks;
    
    this.mCallbacks.customizeUiComponent(this);
    this.mCallbacks.addSuiteTab(this);
  }
  
  public void addComponent(JPanel customPanel)
  {
    add(customPanel);
    revalidate();
    doLayout();
  }
  
  @Override
  public String getTabCaption()
  {
    return this.tabName;
  }
  
  @Override
  public Component getUiComponent()
  {
    return this;
  }
}