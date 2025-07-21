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

package com.contrastsecurity.workflowapprovaltool;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.OperationCanceledException;
import org.eclipse.core.runtime.SubMonitor;
import org.eclipse.jface.operation.IRunnableWithProgress;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.swt.widgets.Shell;

import com.contrastsecurity.workflowapprovaltool.api.Api;
import com.contrastsecurity.workflowapprovaltool.api.ApprovalWorkflowApi;
import com.contrastsecurity.workflowapprovaltool.json.PendingStatusApprovalJson;
import com.contrastsecurity.workflowapprovaltool.model.ItemForVulnerability;
import com.contrastsecurity.workflowapprovaltool.model.Organization;

public class PendingStatusApprovalWithProgress implements IRunnableWithProgress {

    private Shell shell;
    private PreferenceStore ps;
    private Map<Organization, List<ItemForVulnerability>> targetMap;
    private boolean approved;
    private PendingStatusApprovalJson json;

    Logger logger = LogManager.getLogger("csvdltool"); //$NON-NLS-1$

    public PendingStatusApprovalWithProgress(Shell shell, PreferenceStore ps, Map<Organization, List<ItemForVulnerability>> targetMap, boolean approved) {
        this.shell = shell;
        this.ps = ps;
        this.targetMap = targetMap;
        this.approved = approved;
    }

    @Override
    public void run(IProgressMonitor monitor) throws InvocationTargetException, InterruptedException {
        SubMonitor subMonitor = SubMonitor.convert(monitor).setWorkRemaining(100 * this.targetMap.size());
        monitor.setTaskName(Messages.getString("attackeventsgetwithprogress.progress.loading.attackevents.organization.name")); //$NON-NLS-1$

        for (Map.Entry<Organization, List<ItemForVulnerability>> entry : this.targetMap.entrySet()) {
            Organization org = entry.getKey();
            List<ItemForVulnerability> vulns = entry.getValue();
            try {
                monitor.setTaskName(String.format("%s %s", org.getName(), //$NON-NLS-1$
                        Messages.getString("attackeventsgetwithprogress.progress.loading.attackevents.organization.name"))); //$NON-NLS-1$
                monitor.subTask(Messages.getString("attackeventsgetwithprogress.progress.loading.attacks")); //$NON-NLS-1$
                Api pendingStatusApprovalApi = new ApprovalWorkflowApi(this.shell, this.ps, org, vulns, this.approved);
                PendingStatusApprovalJson resJson = (PendingStatusApprovalJson) pendingStatusApprovalApi.post();
                System.out.println(resJson);
                this.json = resJson;
                // monitor.subTask(String.format("%s(%d/%d)", Messages.getString("attackeventsgetwithprogress.progress.loading.attacks"), attackProcessCount, totalTracesCount));
                Thread.sleep(500);
            } catch (OperationCanceledException oce) {
                throw new InvocationTargetException(new OperationCanceledException(Messages.getString("attackeventsgetwithprogress.progress.canceled")));
            } catch (Exception e) {
                throw new InvocationTargetException(e);
            }
        }
        subMonitor.done();
    }

    public PendingStatusApprovalJson getJson() {
        return json;
    }

}
