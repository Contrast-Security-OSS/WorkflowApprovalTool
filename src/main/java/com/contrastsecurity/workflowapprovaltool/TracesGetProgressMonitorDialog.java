package com.contrastsecurity.workflowapprovaltool;

import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.swt.widgets.Shell;

public class TracesGetProgressMonitorDialog extends ProgressMonitorDialog {

    public TracesGetProgressMonitorDialog(Shell parent) {
        super(parent);
    }

    @Override
    protected void configureShell(Shell newShell) {
        super.configureShell(newShell);
        newShell.setText(Messages.getString("attackgetprogressmonitordialog.title")); //$NON-NLS-1$
    }

}
