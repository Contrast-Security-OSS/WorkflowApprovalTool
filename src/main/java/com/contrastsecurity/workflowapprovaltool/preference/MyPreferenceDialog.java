package com.contrastsecurity.workflowapprovaltool.preference;

import org.eclipse.jface.preference.PreferenceDialog;
import org.eclipse.jface.preference.PreferenceManager;
import org.eclipse.jface.viewers.AbstractTreeViewer;
import org.eclipse.jface.viewers.TreeViewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Shell;

import com.contrastsecurity.workflowapprovaltool.Messages;

public class MyPreferenceDialog extends PreferenceDialog {

    public MyPreferenceDialog(Shell parentShell, PreferenceManager manager) {
        super(parentShell, manager);
        setShellStyle(SWT.CLOSE | SWT.TITLE | SWT.MAX | SWT.RESIZE | SWT.APPLICATION_MODAL);
    }

    @Override
    protected void configureShell(Shell newShell) {
        super.configureShell(newShell);
        newShell.setText(Messages.getString("MyPreferenceDialog.preference_dialog_title")); //$NON-NLS-1$
    }

    @Override
    protected TreeViewer createTreeViewer(Composite parent) {
        TreeViewer viewer = super.createTreeViewer(parent);
        viewer.setAutoExpandLevel(AbstractTreeViewer.ALL_LEVELS);
        return viewer;
    }

}
