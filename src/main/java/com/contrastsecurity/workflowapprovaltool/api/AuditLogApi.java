/*
 * MIT License
 * Copyright (c) 2020 Contrast Security Japan G.K.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

package com.contrastsecurity.workflowapprovaltool.api;

import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.regex.Pattern;

import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.swt.widgets.Shell;

import com.contrastsecurity.workflowapprovaltool.model.Organization;

public abstract class AuditLogApi extends Api {

    protected Date startDate;
    protected Date endDate;
    protected int offset;
    protected final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd"); //$NON-NLS-1$
    protected final DateTimeFormatter datetimeformatter = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"); //$NON-NLS-1$
    protected final Pattern userPtn0 = Pattern.compile("Users .+ added to .+ Access Group (\\S+)"); //$NON-NLS-1$
    protected final Pattern userPtn1 = Pattern.compile("Users? (\\S+) .+$"); //$NON-NLS-1$
    protected final Pattern userPtn2 = Pattern.compile(" -  (\\S+) .+ was logged out due to inactivity\\.$"); //$NON-NLS-1$
    protected final Pattern userPtn3 = Pattern.compile(" -  (\\S+) .+ was logged out due to exceeding absolute timeout\\.$"); //$NON-NLS-1$
    protected final Pattern userPtn4 = Pattern.compile(" -  (\\S+) .+ successfully logged out\\.$"); //$NON-NLS-1$
    protected final Pattern userPtn5 = Pattern.compile("\\[(\\S+) impersonating .+$"); //$NON-NLS-1$
    protected final Pattern userPtn6 = Pattern.compile(" by (\\S+).+$"); //$NON-NLS-1$
    protected final Pattern userPtn7 = Pattern.compile("(\\S+) toggle to admin"); //$NON-NLS-1$

    public AuditLogApi(Shell shell, IPreferenceStore ps, Organization org, Date startDate, Date endDate, int offset) {
        super(shell, ps, org);
        this.startDate = startDate;
        this.endDate = endDate;
        this.offset = offset;
    }

}
