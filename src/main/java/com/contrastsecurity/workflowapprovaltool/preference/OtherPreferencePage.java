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

package com.contrastsecurity.workflowapprovaltool.preference;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.jface.preference.PreferencePage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;

import com.contrastsecurity.workflowapprovaltool.Messages;

public class OtherPreferencePage extends PreferencePage {

    private Combo termStartMonthCombo;
    Pattern ptn = Pattern.compile("^[0-9]{2}-[0-9]{2}$"); //$NON-NLS-1$
    public static String[] MONTHS = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Oct", "Nov", "Dec" }; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$ //$NON-NLS-6$ //$NON-NLS-7$ //$NON-NLS-8$ //$NON-NLS-9$ //$NON-NLS-10$ //$NON-NLS-11$
    public static String[] WEEKDAYS = { Messages.getString("OtherPreferencePage.start_weekday_sunday"), Messages.getString("OtherPreferencePage.start_weekday_monday"), //$NON-NLS-1$ //$NON-NLS-2$
            Messages.getString("OtherPreferencePage.start_weekday_tuesday"), Messages.getString("OtherPreferencePage.start_weekday_wednesday"), //$NON-NLS-1$ //$NON-NLS-2$
            Messages.getString("OtherPreferencePage.start_weekday_thursday"), Messages.getString("OtherPreferencePage.start_weekday_friday"), //$NON-NLS-1$ //$NON-NLS-2$
            Messages.getString("OtherPreferencePage.start_weekday_saturday") }; //$NON-NLS-1$
    private List<Button> weekDayBtns = new ArrayList<Button>();

    public OtherPreferencePage() {
        super(Messages.getString("OtherPreferencePage.other_settings_title")); //$NON-NLS-1$
    }

    @Override
    protected Control createContents(Composite parent) {
        IPreferenceStore ps = getPreferenceStore();

        final Composite composite = new Composite(parent, SWT.NONE);
        GridLayout compositeLt = new GridLayout(1, false);
        compositeLt.marginHeight = 15;
        compositeLt.marginWidth = 5;
        compositeLt.horizontalSpacing = 10;
        compositeLt.verticalSpacing = 20;
        composite.setLayout(compositeLt);

        Group protectGrp = new Group(composite, SWT.NONE);
        GridLayout protectGrpLt = new GridLayout(2, false);
        protectGrpLt.marginHeight = 10;
        protectGrpLt.marginWidth = 15;
        protectGrpLt.horizontalSpacing = 10;
        protectGrpLt.verticalSpacing = 15;
        protectGrp.setLayout(protectGrpLt);
        GridData protectGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        protectGrp.setLayoutData(protectGrpGrDt);
        protectGrp.setText(Messages.getString("OtherPreferencePage.target_term_settings_group_title")); //$NON-NLS-1$

        new Label(protectGrp, SWT.LEFT).setText(Messages.getString("OtherPreferencePage.first_month_label_title")); //$NON-NLS-1$
        termStartMonthCombo = new Combo(protectGrp, SWT.DROP_DOWN | SWT.READ_ONLY);
        termStartMonthCombo.setItems(MONTHS);
        termStartMonthCombo.setText(ps.getString(PreferenceConstants.TERM_START_MONTH));

        Group weekDayGrp = new Group(protectGrp, SWT.NONE);
        GridLayout weekDayGrpLt = new GridLayout(7, false);
        weekDayGrpLt.horizontalSpacing = 10;
        weekDayGrp.setLayout(weekDayGrpLt);
        GridData weekDayGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        weekDayGrpGrDt.horizontalSpan = 2;
        weekDayGrp.setLayoutData(weekDayGrpGrDt);
        weekDayGrp.setText(Messages.getString("OtherPreferencePage.start_weekday_label_title")); //$NON-NLS-1$
        int weekDayIdx = 0;
        for (String weekDay : WEEKDAYS) {
            Button weekDayBtn = new Button(weekDayGrp, SWT.RADIO);
            weekDayBtn.setText(weekDay);
            if (ps.getInt(PreferenceConstants.START_WEEKDAY) == weekDayIdx) {
                weekDayBtn.setSelection(true);
            } else {
                weekDayBtn.setSelection(false);
            }
            weekDayBtns.add(weekDayBtn);
            weekDayIdx++;
        }

        Composite buttonGrp = new Composite(parent, SWT.NONE);
        GridLayout buttonGrpLt = new GridLayout(2, false);
        buttonGrpLt.marginHeight = 15;
        buttonGrpLt.marginWidth = 5;
        buttonGrpLt.horizontalSpacing = 7;
        buttonGrpLt.verticalSpacing = 20;
        buttonGrp.setLayout(buttonGrpLt);
        GridData buttonGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        buttonGrpGrDt.horizontalAlignment = SWT.END;
        buttonGrp.setLayoutData(buttonGrpGrDt);

        Button defaultBtn = new Button(buttonGrp, SWT.NULL);
        GridData defaultBtnGrDt = new GridData(SWT.RIGHT, SWT.BOTTOM, true, true, 1, 1);
        defaultBtnGrDt.widthHint = 90;
        defaultBtn.setLayoutData(defaultBtnGrDt);
        defaultBtn.setText(Messages.getString("OtherPreferencePage.restore_defaults_button_title")); //$NON-NLS-1$
        defaultBtn.addSelectionListener(new SelectionAdapter() {
            public void widgetSelected(SelectionEvent e) {
                termStartMonthCombo.setText(ps.getDefaultString(PreferenceConstants.TERM_START_MONTH));
                for (Button btn : weekDayBtns) {
                    btn.setSelection(false);
                }
                Button btn = weekDayBtns.get(ps.getDefaultInt(PreferenceConstants.START_WEEKDAY));
                btn.setSelection(true);
            }
        });

        Button applyBtn = new Button(buttonGrp, SWT.NULL);
        GridData applyBtnGrDt = new GridData(SWT.RIGHT, SWT.BOTTOM, true, true, 1, 1);
        applyBtnGrDt.widthHint = 90;
        applyBtn.setLayoutData(applyBtnGrDt);
        applyBtn.setText(Messages.getString("OtherPreferencePage.apply_button_title")); //$NON-NLS-1$
        applyBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                performOk();
            }
        });

        noDefaultAndApplyButton();
        return composite;
    }

    @Override
    public boolean performOk() {
        IPreferenceStore ps = getPreferenceStore();
        if (ps == null) {
            return true;
        }
        List<String> errors = new ArrayList<String>();
        if (!errors.isEmpty()) {
            MessageDialog.openError(getShell(), Messages.getString("OtherPreferencePage.other_settings_title"), String.join("\r\n", errors)); //$NON-NLS-1$ //$NON-NLS-2$
            return false;
        } else {
            ps.setValue(PreferenceConstants.TERM_START_MONTH, this.termStartMonthCombo.getText());
            int weekDaySelection = 0;
            for (Button btn : weekDayBtns) {
                if (btn.getSelection()) {
                    break;
                }
                weekDaySelection++;
            }
            ps.setValue(PreferenceConstants.START_WEEKDAY, weekDaySelection);
        }
        return true;
    }
}
