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

package burp;

import authheaderupdater.*;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.List;


public class BurpExtender implements burp.IBurpExtender, burp.IHttpListener
{
    private burp.IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private OutputStream output;
    private TabComponent comp;

    @Override
    public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks)
    {
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(),true);
        this.output = callbacks.getStdout();

        // set our extension name
        callbacks.setExtensionName("Auth Header Updater");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
        
        //Add UI
        Tab tab = new Tab("Auth Header Updater", callbacks);
        comp = new TabComponent(callbacks, this);
        tab.addComponent(comp); 
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, burp.IHttpRequestResponse messageInfo)
    {        
        if (comp.isEnabled())
        {
            if (messageIsRequest && (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER)) 
            {
                burp.IRequestInfo iRequest = helpers.analyzeRequest(messageInfo);
                String request = new String(messageInfo.getRequest());
                List<String> headers = iRequest.getHeaders();
                String reqBody = request.substring(iRequest.getBodyOffset());
                boolean updated = false;

                for (int i = 0; i < headers.size(); i++)
                {
                    String header = headers.get(i);

                    if (header.toLowerCase().contains("authorization: bearer")) 
                    {
                        header = "Authorization: Bearer " + comp.getToken();
                        headers.set(i, header);
                        updated = true;
                    }                
                }

                if (updated) 
                {
                    byte[] message = helpers.buildHttpMessage(headers, reqBody.getBytes());
                    messageInfo.setRequest(message);
                }
            }
        }
    }
    
    public void println(String toPrint)
    {
        try
        {
            this.output.write(toPrint.getBytes());
            this.output.write("\n".getBytes());
            this.output.flush();
        } 
        catch (IOException ioe)
        {
        }
    }
}
