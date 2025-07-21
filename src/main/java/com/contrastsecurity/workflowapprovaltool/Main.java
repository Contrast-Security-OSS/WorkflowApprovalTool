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

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.text.SimpleDateFormat;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;

import org.apache.commons.exec.OS;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.jface.preference.PreferenceDialog;
import org.eclipse.jface.preference.PreferenceManager;
import org.eclipse.jface.preference.PreferenceNode;
import org.eclipse.jface.preference.PreferenceStore;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.TableEditor;
import org.eclipse.swt.events.KeyAdapter;
import org.eclipse.swt.events.KeyEvent;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.ShellEvent;
import org.eclipse.swt.events.ShellListener;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.graphics.Font;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;
import org.eclipse.swt.widgets.Table;
import org.eclipse.swt.widgets.TableColumn;
import org.eclipse.swt.widgets.TableItem;
import org.eclipse.swt.widgets.Text;
import org.yaml.snakeyaml.Yaml;

import com.contrastsecurity.workflowapprovaltool.exception.ApiException;
import com.contrastsecurity.workflowapprovaltool.exception.NonApiException;
import com.contrastsecurity.workflowapprovaltool.model.ContrastSecurityYaml;
import com.contrastsecurity.workflowapprovaltool.model.Filter;
import com.contrastsecurity.workflowapprovaltool.model.ItemForVulnerability;
import com.contrastsecurity.workflowapprovaltool.model.Note;
import com.contrastsecurity.workflowapprovaltool.model.Organization;
import com.contrastsecurity.workflowapprovaltool.preference.AboutPage;
import com.contrastsecurity.workflowapprovaltool.preference.BasePreferencePage;
import com.contrastsecurity.workflowapprovaltool.preference.ConnectionPreferencePage;
import com.contrastsecurity.workflowapprovaltool.preference.MyPreferenceDialog;
import com.contrastsecurity.workflowapprovaltool.preference.OtherPreferencePage;
import com.contrastsecurity.workflowapprovaltool.preference.PreferenceConstants;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

public class Main implements PropertyChangeListener {

    public static final String WINDOW_TITLE = "WorkflowApprovalTool - %s";
    // 以下のMASTER_PASSWORDはプロキシパスワードを保存する際に暗号化で使用するパスワードです。
    // 本ツールをリリース用にコンパイルする際はchangemeを別の文字列に置き換えてください。
    public static final String MASTER_PASSWORD = "changeme!";

    // 各出力ファイルの文字コード
    public static final String CSV_WIN_ENCODING = "Shift_JIS";
    public static final String CSV_MAC_ENCODING = "UTF-8";
    public static final String FILE_ENCODING = "UTF-8";

    public static final int MINIMUM_SIZE_WIDTH = 800;
    public static final int MINIMUM_SIZE_WIDTH_MAC = 880;
    public static final int MINIMUM_SIZE_HEIGHT = 640;

    private AuditLogToolShell shell;

    private Button auditLogLoadBtn;

    private Button settingBtn;

    private Label statusBar;

    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd(E)");

    private Map<FilterEnum, Set<Filter>> auditLogFilterMap;

    private boolean isBulkOn;
    private boolean isFirstDetectSortDesc;
    private boolean isLastDetectSortDesc;

    // AuditLog
    private Label auditLogCount;
    private Button firstDetect;
    private Button lastDetect;
    private List<Button> auditLogCreatedRadios = new ArrayList<Button>();
    private Button auditLogTermHalf1st;
    private Button auditLogTermHalf2nd;
    private Button auditLogTerm30days;
    private Button auditLogTermYesterday;
    private Button auditLogTermToday;
    private Button auditLogTermLastWeek;
    private Button auditLogTermThisWeek;
    private Button auditLogTermPeriod;
    private Text auditLogCreatedFilterTxt;
    private Date frCreatedDate;
    private Date toCreatedDate;
    private Table pendingVulTable;
    private List<Button> checkBoxList = new ArrayList<Button>();
    private List<Integer> selectedIdxes = new ArrayList<Integer>();
    private Text noteTxt;
    private List<ItemForVulnerability> auditLogs;
    private List<ItemForVulnerability> filteredAuditLogs = new ArrayList<ItemForVulnerability>();
    private Map<AuditLogCreatedDateFilterEnum, Date> auditLogCreatedFilterMap;
    private Button approveBtn;
    private Button rejectBtn;

    private PreferenceStore ps;

    private PropertyChangeSupport support = new PropertyChangeSupport(this);

    Logger logger = LogManager.getLogger("workflowapprovaltool");

    /**
     * @param args
     */
    public static void main(String[] args) {
        Main main = new Main();
        main.initialize();
        main.createPart();
    }

    private void initialize() {
        try {
            String homeDir = System.getProperty("user.home");
            this.ps = new PreferenceStore(homeDir + "\\workflowapprovaltool.properties");
            if (OS.isFamilyMac()) {
                this.ps = new PreferenceStore(homeDir + "/workflowapprovaltool.properties");
            }
            try {
                this.ps.load();
            } catch (FileNotFoundException fnfe) {
                this.ps = new PreferenceStore("workflowapprovaltool.properties");
                this.ps.load();
            }
        } catch (FileNotFoundException fnfe) {
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            this.ps.setDefault(PreferenceConstants.IS_SUPERADMIN, "false");
            this.ps.setDefault(PreferenceConstants.IS_CREATEGROUP, "false");
            this.ps.setDefault(PreferenceConstants.GROUP_NAME, "GgHTWED8kZdQU76c");
            this.ps.setDefault(PreferenceConstants.PROXY_AUTH, "none");
            this.ps.setDefault(PreferenceConstants.CONNECTION_TIMEOUT, 3000);
            this.ps.setDefault(PreferenceConstants.SOCKET_TIMEOUT, 3000);

            this.ps.setDefault(PreferenceConstants.DETECT_CHOICE, "FIRST");
            this.ps.setDefault(PreferenceConstants.TERM_START_MONTH, "Jan");
            this.ps.setDefault(PreferenceConstants.START_WEEKDAY, 1); // 月曜日
            this.ps.setDefault(PreferenceConstants.AUDITLOG_CREATED_DATE_FILTER, 0);

            this.ps.setDefault(PreferenceConstants.OPENED_MAIN_TAB_IDX, 0);
            this.ps.setDefault(PreferenceConstants.OPENED_SUB_TAB_IDX, 0);

            Yaml yaml = new Yaml();
            InputStream is = new FileInputStream("contrast_security.yaml");
            ContrastSecurityYaml contrastSecurityYaml = yaml.loadAs(is, ContrastSecurityYaml.class);
            is.close();
            this.ps.setDefault(PreferenceConstants.CONTRAST_URL, contrastSecurityYaml.getUrl());
            this.ps.setDefault(PreferenceConstants.USERNAME, contrastSecurityYaml.getUserName());
            this.ps.setDefault(PreferenceConstants.SERVICE_KEY, contrastSecurityYaml.getServiceKey());
        } catch (Exception e) {
            // e.printStackTrace();
        }
    }

    private void createPart() {
        Display display = new Display();
        shell = new AuditLogToolShell(display, this);
        if (OS.isFamilyMac()) {
            shell.setMinimumSize(MINIMUM_SIZE_WIDTH_MAC, MINIMUM_SIZE_HEIGHT);
        } else {
            shell.setMinimumSize(MINIMUM_SIZE_WIDTH, MINIMUM_SIZE_HEIGHT);
        }
        Image[] imageArray = new Image[5];
        imageArray[0] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon16.png"));
        imageArray[1] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon24.png"));
        imageArray[2] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon32.png"));
        imageArray[3] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon48.png"));
        imageArray[4] = new Image(display, Main.class.getClassLoader().getResourceAsStream("icon128.png"));
        shell.setImages(imageArray);
        Window.setDefaultImages(imageArray);
        setWindowTitle();
        shell.addShellListener(new ShellListener() {
            @Override
            public void shellIconified(ShellEvent event) {
            }

            @Override
            public void shellDeiconified(ShellEvent event) {
            }

            @Override
            public void shellDeactivated(ShellEvent event) {
            }

            @Override
            public void shellClosed(ShellEvent event) {
                ps.setValue(PreferenceConstants.MEM_WIDTH, shell.getSize().x);
                ps.setValue(PreferenceConstants.MEM_HEIGHT, shell.getSize().y);
                ps.setValue(PreferenceConstants.PROXY_TMP_USER, "");
                ps.setValue(PreferenceConstants.PROXY_TMP_PASS, "");
                if (firstDetect.getSelection()) {
                    ps.setValue(PreferenceConstants.DETECT_CHOICE, "FIRST");
                } else {
                    ps.setValue(PreferenceConstants.DETECT_CHOICE, "LAST");
                }
                for (Button termBtn : auditLogCreatedRadios) {
                    if (termBtn.getSelection()) {
                        ps.setValue(PreferenceConstants.AUDITLOG_CREATED_DATE_FILTER, auditLogCreatedRadios.indexOf(termBtn));
                    }
                }
                try {
                    ps.save();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                }
            }

            @Override
            public void shellActivated(ShellEvent event) {
                boolean ngRequiredFields = false;
                String url = ps.getString(PreferenceConstants.CONTRAST_URL);
                String usr = ps.getString(PreferenceConstants.USERNAME);
                boolean isSuperAdmin = ps.getBoolean(PreferenceConstants.IS_SUPERADMIN);
                String svc = ps.getString(PreferenceConstants.SERVICE_KEY);
                if (isSuperAdmin) {
                    String api = ps.getString(PreferenceConstants.API_KEY);
                    if (url.isEmpty() || usr.isEmpty() || svc.isEmpty() || api.isEmpty()) {
                        ngRequiredFields = true;
                    }
                } else {
                    if (url.isEmpty() || usr.isEmpty() || svc.isEmpty()) {
                        ngRequiredFields = true;
                    }
                }
                List<Organization> orgs = getValidOrganizations();
                if (ngRequiredFields || (!isSuperAdmin && orgs.isEmpty())) {
                    auditLogLoadBtn.setEnabled(false);
                    settingBtn.setText("このボタンから基本設定を行ってください。");
                    uiReset();
                } else {
                    auditLogLoadBtn.setEnabled(true);
                    settingBtn.setText("設定");
                }
                updateProtectOption();
                setWindowTitle();
                if (ps.getBoolean(PreferenceConstants.PROXY_YUKO) && ps.getString(PreferenceConstants.PROXY_AUTH).equals("input")) {
                    String proxy_usr = ps.getString(PreferenceConstants.PROXY_TMP_USER);
                    String proxy_pwd = ps.getString(PreferenceConstants.PROXY_TMP_PASS);
                    if (proxy_usr == null || proxy_usr.isEmpty() || proxy_pwd == null || proxy_pwd.isEmpty()) {
                        ProxyAuthDialog proxyAuthDialog = new ProxyAuthDialog(shell);
                        int result = proxyAuthDialog.open();
                        if (IDialogConstants.CANCEL_ID == result) {
                            ps.setValue(PreferenceConstants.PROXY_AUTH, "none");
                        } else {
                            ps.setValue(PreferenceConstants.PROXY_TMP_USER, proxyAuthDialog.getUsername());
                            ps.setValue(PreferenceConstants.PROXY_TMP_PASS, proxyAuthDialog.getPassword());
                        }
                    }
                }
            }
        });

        GridLayout baseLayout = new GridLayout(1, false);
        baseLayout.marginWidth = 8;
        baseLayout.marginBottom = 0;
        baseLayout.verticalSpacing = 8;
        shell.setLayout(baseLayout);

        Group auditLogListGrp = new Group(shell, SWT.NONE);
        auditLogListGrp.setLayout(new GridLayout(3, false));
        GridData auditLogListGrpGrDt = new GridData(GridData.FILL_BOTH);
        auditLogListGrpGrDt.minimumHeight = 200;
        auditLogListGrp.setLayoutData(auditLogListGrpGrDt);

        Composite detectGrp = new Composite(auditLogListGrp, SWT.NONE);
        detectGrp.setLayout(new GridLayout(10, false));
        GridData detectGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        detectGrp.setLayoutData(detectGrpGrDt);

        firstDetect = new Button(detectGrp, SWT.RADIO);
        firstDetect.setText("最初の検出");
        firstDetect.setSelection(false);
        lastDetect = new Button(detectGrp, SWT.RADIO);
        lastDetect.setText("最後の検出");
        lastDetect.setSelection(false);
        if (this.ps.getString(PreferenceConstants.DETECT_CHOICE).equals("FIRST")) {
            firstDetect.setSelection(true);
        } else {
            lastDetect.setSelection(true);
        }

        Composite auditLogTermGrp = new Composite(auditLogListGrp, SWT.NONE);
        auditLogTermGrp.setLayout(new GridLayout(10, false));
        GridData auditLogTermGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        auditLogTermGrpGrDt.horizontalSpan = 3;
        auditLogTermGrp.setLayoutData(auditLogTermGrpGrDt);

        new Label(auditLogTermGrp, SWT.LEFT).setText("取得期間：");
        // =============== 取得期間選択ラジオボタン ===============
        // 上半期
        auditLogTermHalf1st = new Button(auditLogTermGrp, SWT.RADIO);
        auditLogTermHalf1st.setText("上半期");
        auditLogCreatedRadios.add(auditLogTermHalf1st);
        auditLogTermHalf1st.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_1ST_START);
                toCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_1ST_END);
                detectedDateLabelUpdate();
            }

        });
        // 下半期
        auditLogTermHalf2nd = new Button(auditLogTermGrp, SWT.RADIO);
        auditLogTermHalf2nd.setText("下半期");
        auditLogCreatedRadios.add(auditLogTermHalf2nd);
        auditLogTermHalf2nd.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_2ND_START);
                toCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_2ND_END);
                detectedDateLabelUpdate();
            }

        });
        // 直近30日間
        auditLogTerm30days = new Button(auditLogTermGrp, SWT.RADIO);
        auditLogTerm30days.setText("直近30日間");
        auditLogCreatedRadios.add(auditLogTerm30days);
        auditLogTerm30days.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.BEFORE_30_DAYS);
                toCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.TODAY);
                detectedDateLabelUpdate();
            }
        });
        // 昨日
        auditLogTermYesterday = new Button(auditLogTermGrp, SWT.RADIO);
        auditLogTermYesterday.setText("昨日");
        auditLogCreatedRadios.add(auditLogTermYesterday);
        auditLogTermYesterday.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.YESTERDAY);
                toCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.YESTERDAY);
                detectedDateLabelUpdate();
            }
        });
        // 今日
        auditLogTermToday = new Button(auditLogTermGrp, SWT.RADIO);
        auditLogTermToday.setText("今日");
        auditLogCreatedRadios.add(auditLogTermToday);
        auditLogTermToday.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.TODAY);
                toCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.TODAY);
                detectedDateLabelUpdate();
            }
        });
        // 先週
        auditLogTermLastWeek = new Button(auditLogTermGrp, SWT.RADIO);
        auditLogTermLastWeek.setText("先週");
        auditLogCreatedRadios.add(auditLogTermLastWeek);
        auditLogTermLastWeek.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.LAST_WEEK_START);
                toCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.LAST_WEEK_END);
                detectedDateLabelUpdate();
            }
        });
        // 今週
        auditLogTermThisWeek = new Button(auditLogTermGrp, SWT.RADIO);
        auditLogTermThisWeek.setText("今週");
        auditLogCreatedRadios.add(auditLogTermThisWeek);
        auditLogTermThisWeek.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                frCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.THIS_WEEK_START);
                toCreatedDate = auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.THIS_WEEK_END);
                detectedDateLabelUpdate();
            }
        });
        // 任意機関
        auditLogTermPeriod = new Button(auditLogTermGrp, SWT.RADIO);
        auditLogTermPeriod.setText("任意");
        auditLogCreatedRadios.add(auditLogTermPeriod);
        auditLogTermPeriod.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
            }
        });
        auditLogCreatedFilterTxt = new Text(auditLogTermGrp, SWT.BORDER);
        auditLogCreatedFilterTxt.setText("");
        auditLogCreatedFilterTxt.setEditable(false);
        auditLogCreatedFilterTxt.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        auditLogCreatedFilterTxt.addListener(SWT.MouseUp, new Listener() {
            public void handleEvent(Event e) {
                if (!auditLogTermPeriod.getSelection()) {
                    return;
                }
                FilterCreatedDateDialog filterDialog = new FilterCreatedDateDialog(shell, frCreatedDate, toCreatedDate);
                int result = filterDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    auditLogLoadBtn.setFocus();
                    return;
                }
                frCreatedDate = filterDialog.getFrDate();
                toCreatedDate = filterDialog.getToDate();
                detectedDateLabelUpdate();
                if (!auditLogCreatedFilterTxt.getText().isEmpty()) {
                    for (Button rdo : auditLogCreatedRadios) {
                        rdo.setSelection(false);
                    }
                    auditLogTermPeriod.setSelection(true);
                }
                auditLogLoadBtn.setFocus();
            }
        });
        for (Button termBtn : this.auditLogCreatedRadios) {
            updateProtectOption();
            termBtn.setSelection(false);
            if (this.auditLogCreatedRadios.indexOf(termBtn) == this.ps.getInt(PreferenceConstants.AUDITLOG_CREATED_DATE_FILTER)) {
                termBtn.setSelection(true);
                Event event = new Event();
                event.widget = termBtn;
                event.type = SWT.Selection;
                termBtn.notifyListeners(SWT.Selection, event);
            }
        }
        detectedDateLabelUpdate();

        auditLogLoadBtn = new Button(auditLogListGrp, SWT.PUSH);
        GridData auditLogLoadBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        auditLogLoadBtnGrDt.horizontalSpan = 3;
        auditLogLoadBtnGrDt.heightHint = 40;
        auditLogLoadBtn.setLayoutData(auditLogLoadBtnGrDt);
        auditLogLoadBtn.setText("保留中の脆弱性を取得");
        auditLogLoadBtn.setToolTipText("監査ログを取得します。");
        auditLogLoadBtn.setFont(new Font(display, "ＭＳ ゴシック", 18, SWT.NORMAL));
        auditLogLoadBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                filteredAuditLogs.clear();
                pendingVulTable.clearAll();
                pendingVulTable.removeAll();
                for (Button button : checkBoxList) {
                    button.dispose();
                }
                checkBoxList.clear();
                Date[] frToDate = getFrToDetectedDate();
                if (frToDate.length != 2) {
                    MessageDialog.openError(shell, "監査ログの取得", "取得期間を設定してください。");
                    return;
                }
                String detectChoice = "FIRST";
                if (lastDetect.getSelection()) {
                    detectChoice = "LAST";
                }

                TracesGetWithProgress progress = new TracesGetWithProgress(shell, ps, getValidOrganizations(), detectChoice, frToDate[0], frToDate[1]);
                ProgressMonitorDialog progDialog = new TracesGetProgressMonitorDialog(shell);
                try {
                    progDialog.run(true, true, progress);
                    auditLogs = progress.getAllAttackEvents();
                    Collections.sort(auditLogs, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                        }
                    });
                    filteredAuditLogs.addAll(auditLogs);
                    for (ItemForVulnerability attackEvent : auditLogs) {
                        addColToPendingVulTable(attackEvent, -1);
                    }
                    auditLogFilterMap = progress.getFilterMap();
                    auditLogCount.setText(String.format("%d/%d", filteredAuditLogs.size(), auditLogs.size())); //$NON-NLS-1$
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(shell, "監査ログの取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        this.auditLogCount = new Label(auditLogListGrp, SWT.RIGHT);
        GridData auditLogCountGrDt = new GridData(GridData.FILL_HORIZONTAL);
        auditLogCountGrDt.horizontalSpan = 3;
        auditLogCountGrDt.minimumHeight = 12;
        auditLogCountGrDt.minimumWidth = 30;
        auditLogCountGrDt.heightHint = 12;
        auditLogCountGrDt.widthHint = 30;
        this.auditLogCount.setLayoutData(auditLogCountGrDt);
        this.auditLogCount.setFont(new Font(display, "ＭＳ ゴシック", 10, SWT.NORMAL));
        this.auditLogCount.setText("0/0");

        pendingVulTable = new Table(auditLogListGrp, SWT.BORDER | SWT.FULL_SELECTION | SWT.MULTI);
        GridData tableGrDt = new GridData(GridData.FILL_BOTH);
        tableGrDt.horizontalSpan = 3;
        pendingVulTable.setLayoutData(tableGrDt);
        pendingVulTable.setLinesVisible(true);
        pendingVulTable.setHeaderVisible(true);
        Menu menuTable = new Menu(pendingVulTable);
        pendingVulTable.setMenu(menuTable);

        MenuItem miSelectAll = new MenuItem(menuTable, SWT.NONE);
        if (OS.isFamilyMac()) {
            miSelectAll.setText("すべて選択（Command + A）");
        } else {
            miSelectAll.setText("すべて選択（Ctrl + A）");
        }
        miSelectAll.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                pendingVulTable.selectAll();
            }
        });

        pendingVulTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if ((e.stateMask == SWT.CTRL || e.stateMask == SWT.COMMAND) && e.keyCode == 'a') {
                    pendingVulTable.selectAll();
                    e.doit = false;
                }
            }
        });

        pendingVulTable.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                ItemForVulnerability selectedVul = filteredAuditLogs.get(pendingVulTable.getSelectionIndex());
                List<String> lines = new ArrayList<String>();
                for (Note note : selectedVul.getVulnerability().getNotes()) {
                    lines.add(note.getNote());
                }
                noteTxt.setText(String.join(System.getProperty("line.separator"), lines));
            }
        });

        TableColumn column0 = new TableColumn(pendingVulTable, SWT.NONE);
        column0.setWidth(0);
        column0.setResizable(false);
        TableColumn column1 = new TableColumn(pendingVulTable, SWT.CENTER);
        column1.setWidth(50);
        column1.setText("有効");
        column1.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isBulkOn = !isBulkOn;
                if (selectedIdxes.isEmpty()) {
                    isBulkOn = true;
                } else {
                    if (filteredAuditLogs.size() == selectedIdxes.size()) {
                        isBulkOn = false;
                    }
                }
                if (isBulkOn) {
                    selectedIdxes.clear();
                    for (Button button : checkBoxList) {
                        button.setSelection(true);
                        selectedIdxes.add(checkBoxList.indexOf(button));
                    }
                } else {
                    selectedIdxes.clear();
                    for (Button button : checkBoxList) {
                        button.setSelection(false);
                    }
                }
                updateAuthorizeBtn();
            }
        });
        TableColumn column2 = new TableColumn(pendingVulTable, SWT.CENTER);
        column2.setWidth(150);
        column2.setText("最初の検知日時");
        column2.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isFirstDetectSortDesc = !isFirstDetectSortDesc;
                pendingVulTable.clearAll();
                pendingVulTable.removeAll();
                if (isFirstDetectSortDesc) {
                    Collections.reverse(auditLogs);
                    Collections.reverse(filteredAuditLogs);
                } else {
                    Collections.sort(auditLogs, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                        }
                    });
                    Collections.sort(filteredAuditLogs, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                        }
                    });
                }
                for (ItemForVulnerability vul : filteredAuditLogs) {
                    addColToPendingVulTable(vul, -1);
                }
            }
        });
        TableColumn column3 = new TableColumn(pendingVulTable, SWT.CENTER);
        column3.setWidth(150);
        column3.setText("最後の検知日時");
        column3.addListener(SWT.Selection, new Listener() {
            @Override
            public void handleEvent(Event event) {
                isLastDetectSortDesc = !isLastDetectSortDesc;
                pendingVulTable.clearAll();
                pendingVulTable.removeAll();
                if (isLastDetectSortDesc) {
                    Collections.reverse(auditLogs);
                    Collections.reverse(filteredAuditLogs);
                } else {
                    Collections.sort(auditLogs, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getLastDetected().compareTo(e2.getVulnerability().getLastDetected());
                        }
                    });
                    Collections.sort(filteredAuditLogs, new Comparator<ItemForVulnerability>() {
                        @Override
                        public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                            return e1.getVulnerability().getLastDetected().compareTo(e2.getVulnerability().getLastDetected());
                        }
                    });
                }
                for (ItemForVulnerability vul : filteredAuditLogs) {
                    addColToPendingVulTable(vul, -1);
                }
            }
        });
        TableColumn column4 = new TableColumn(pendingVulTable, SWT.LEFT);
        column4.setWidth(200);
        column4.setText("脆弱性");
        TableColumn column5 = new TableColumn(pendingVulTable, SWT.CENTER);
        column5.setWidth(200);
        column5.setText("重大度");
        TableColumn column6 = new TableColumn(pendingVulTable, SWT.CENTER);
        column6.setWidth(200);
        column6.setText("ステータス");
        TableColumn column7 = new TableColumn(pendingVulTable, SWT.CENTER);
        column7.setWidth(200);
        column7.setText("保留中ステータス");
        TableColumn column8 = new TableColumn(pendingVulTable, SWT.LEFT);
        column8.setWidth(300);
        column8.setText("アプリケーション");
        TableColumn column9 = new TableColumn(pendingVulTable, SWT.LEFT);
        column9.setWidth(300);
        column9.setText("組織");

        Button auditLogFilterBtn = new Button(auditLogListGrp, SWT.PUSH);
        GridData auditLogFilterBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        auditLogFilterBtnGrDt.horizontalSpan = 3;
        auditLogFilterBtn.setLayoutData(auditLogFilterBtnGrDt);
        auditLogFilterBtn.setText("フィルター");
        auditLogFilterBtn.setToolTipText("監査ログのフィルタリングを行います。");
        auditLogFilterBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                if (auditLogFilterMap == null) {
                    MessageDialog.openInformation(shell, "監査ログフィルター", "監査ログを読み込んでください。");
                    return;
                }
                AttackEventFilterDialog filterDialog = new AttackEventFilterDialog(shell, auditLogFilterMap);
                filterDialog.addPropertyChangeListener(shell.getMain());
                int result = filterDialog.open();
                if (IDialogConstants.OK_ID != result) {
                    return;
                }
            }
        });

        noteTxt = new Text(auditLogListGrp, SWT.BORDER | SWT.MULTI | SWT.READ_ONLY);
        noteTxt.setText("ここに脆弱性のコメントが表示されます。");
        Color white = display.getSystemColor(SWT.COLOR_WHITE);
        noteTxt.setBackground(white);
        GridData noteTxtGrDt = new GridData(GridData.FILL_HORIZONTAL);
        noteTxtGrDt.horizontalSpan = 3;
        noteTxtGrDt.minimumHeight = 100;
        noteTxtGrDt.heightHint = 100;
        noteTxt.setLayoutData(noteTxtGrDt);

        approveBtn = new Button(auditLogListGrp, SWT.PUSH);
        GridData approveBtnGrDt = new GridData(GridData.FILL_HORIZONTAL);
        approveBtnGrDt.horizontalSpan = 2;
        approveBtnGrDt.heightHint = 50;
        approveBtn.setLayoutData(approveBtnGrDt);
        approveBtn.setText("承認");
        approveBtn.setToolTipText("選択されている脆弱性のステータス変更を承認します。");
        approveBtn.setFont(new Font(display, "ＭＳ ゴシック", 20, SWT.BOLD));
        approveBtn.setEnabled(false);
        approveBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                Map<Organization, List<ItemForVulnerability>> targetMap = new HashMap<Organization, List<ItemForVulnerability>>();
                for (Organization org : getValidOrganizations()) {
                    targetMap.put(org, new ArrayList<ItemForVulnerability>());
                }
                for (int idx : selectedIdxes) {
                    ItemForVulnerability vul = filteredAuditLogs.get(idx);
                    targetMap.get(vul.getVulnerability().getOrg()).add(vul);
                }
                PendingStatusApprovalWithProgress progress = new PendingStatusApprovalWithProgress(shell, ps, targetMap, true);
                ProgressMonitorDialog progDialog = new PendingStatusApprovalProgressMonitorDialog(shell);
                try {
                    progDialog.run(true, true, progress);
                    System.out.println(progress.getJson());
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(shell, "監査ログの取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        rejectBtn = new Button(auditLogListGrp, SWT.PUSH);
        GridData rejectBtnGrDt = new GridData();
        rejectBtnGrDt.horizontalSpan = 1;
        rejectBtnGrDt.heightHint = 50;
        rejectBtnGrDt.widthHint = 150;
        rejectBtn.setLayoutData(rejectBtnGrDt);
        rejectBtn.setText("却下");
        rejectBtn.setToolTipText("選択されている脆弱性のステータス変更を却下します。");
        rejectBtn.setFont(new Font(display, "ＭＳ ゴシック", 16, SWT.NORMAL));
        rejectBtn.setEnabled(false);
        rejectBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                Map<Organization, List<ItemForVulnerability>> targetMap = new HashMap<Organization, List<ItemForVulnerability>>();
                for (Organization org : getValidOrganizations()) {
                    targetMap.put(org, new ArrayList<ItemForVulnerability>());
                }
                for (int idx : selectedIdxes) {
                    ItemForVulnerability vul = filteredAuditLogs.get(idx);
                    targetMap.get(vul.getVulnerability().getOrg()).add(vul);
                }
                PendingStatusApprovalWithProgress progress = new PendingStatusApprovalWithProgress(shell, ps, targetMap, false);
                ProgressMonitorDialog progDialog = new PendingStatusApprovalProgressMonitorDialog(shell);
                try {
                    progDialog.run(true, true, progress);
                    System.out.println(progress.getJson());
                } catch (InvocationTargetException e) {
                    StringWriter stringWriter = new StringWriter();
                    PrintWriter printWriter = new PrintWriter(stringWriter);
                    e.printStackTrace(printWriter);
                    String trace = stringWriter.toString();
                    logger.error(trace);
                    String errorMsg = e.getTargetException().getMessage();
                    if (e.getTargetException() instanceof ApiException) {
                        MessageDialog.openWarning(shell, "監査ログの取得", String.format("TeamServerからエラーが返されました。\r\n%s", errorMsg));
                    } else if (e.getTargetException() instanceof NonApiException) {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("想定外のステータスコード: %s\r\nログファイルをご確認ください。", errorMsg));
                    } else {
                        MessageDialog.openError(shell, "監査ログの取得", String.format("不明なエラーです。ログファイルをご確認ください。\r\n%s", errorMsg));
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        Composite bottomBtnGrp = new Composite(shell, SWT.NONE);
        GridLayout bottomBtnGrpLt = new GridLayout();
        bottomBtnGrpLt.numColumns = 1;
        bottomBtnGrpLt.makeColumnsEqualWidth = false;
        bottomBtnGrpLt.marginHeight = 0;
        bottomBtnGrp.setLayout(bottomBtnGrpLt);
        GridData bottomBtnGrpGrDt = new GridData(GridData.FILL_HORIZONTAL);
        bottomBtnGrp.setLayoutData(bottomBtnGrpGrDt);

        // ========== 設定ボタン ==========
        settingBtn = new Button(bottomBtnGrp, SWT.PUSH);
        settingBtn.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));
        settingBtn.setText("設定");
        settingBtn.setToolTipText("動作に必要な設定を行います。");
        settingBtn.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                PreferenceManager mgr = new PreferenceManager();
                PreferenceNode baseNode = new PreferenceNode("base", new BasePreferencePage(shell));
                PreferenceNode connectionNode = new PreferenceNode("connection", new ConnectionPreferencePage());
                PreferenceNode otherNode = new PreferenceNode("other", new OtherPreferencePage());
                mgr.addToRoot(baseNode);
                mgr.addToRoot(connectionNode);
                mgr.addToRoot(otherNode);
                PreferenceNode aboutNode = new PreferenceNode("about", new AboutPage());
                mgr.addToRoot(aboutNode);
                PreferenceDialog dialog = new MyPreferenceDialog(shell, mgr);
                dialog.setPreferenceStore(ps);
                dialog.open();
                try {
                    ps.save();
                } catch (IOException ioe) {
                    ioe.printStackTrace();
                }
            }
        });

        this.statusBar = new Label(shell, SWT.RIGHT);
        GridData statusBarGrDt = new GridData(GridData.FILL_HORIZONTAL);
        statusBarGrDt.minimumHeight = 11;
        statusBarGrDt.heightHint = 11;
        this.statusBar.setLayoutData(statusBarGrDt);
        this.statusBar.setFont(new Font(display, "ＭＳ ゴシック", 9, SWT.NORMAL));
        this.statusBar.setForeground(shell.getDisplay().getSystemColor(SWT.COLOR_DARK_GRAY));

        uiUpdate();
        int width = this.ps.getInt(PreferenceConstants.MEM_WIDTH);
        int height = this.ps.getInt(PreferenceConstants.MEM_HEIGHT);
        if (width > 0 && height > 0) {
            shell.setSize(width, height);
        } else {
            shell.setSize(MINIMUM_SIZE_WIDTH, MINIMUM_SIZE_HEIGHT);
            // shell.pack();
        }
        shell.open();
        try {
            while (!shell.isDisposed()) {
                if (!display.readAndDispatch()) {
                    display.sleep();
                }
            }
        } catch (Exception e) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            e.printStackTrace(printWriter);
            String trace = stringWriter.toString();
            logger.error(trace);
        }
        display.dispose();
    }

    private void detectedDateLabelUpdate() {
        if (frCreatedDate != null && toCreatedDate != null) {
            auditLogCreatedFilterTxt.setText(String.format("%s ～ %s", sdf.format(frCreatedDate), sdf.format(toCreatedDate)));
        } else if (frCreatedDate != null) {
            auditLogCreatedFilterTxt.setText(String.format("%s ～", sdf.format(frCreatedDate)));
        } else if (toCreatedDate != null) {
            auditLogCreatedFilterTxt.setText(String.format("～ %s", sdf.format(toCreatedDate)));
        } else {
            auditLogCreatedFilterTxt.setText("");
        }
    }

    private void addColToPendingVulTable(ItemForVulnerability audit, int index) {
        if (audit == null) {
            return;
        }
        TableEditor editor = new TableEditor(pendingVulTable);
        Button button = new Button(pendingVulTable, SWT.CHECK);
        button.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                selectedIdxes.clear();
                for (Button button : checkBoxList) {
                    if (button.getSelection()) {
                        selectedIdxes.add(checkBoxList.indexOf(button));
                    }
                }
                updateAuthorizeBtn();
            }
        });
        button.pack();
        TableItem item = new TableItem(pendingVulTable, SWT.CENTER);
        editor.minimumWidth = button.getSize().x;
        editor.horizontalAlignment = SWT.CENTER;
        editor.setEditor(button, item, 1);
        checkBoxList.add(button);
        item.setText(2, audit.getVulnerability().getFirstDetectedStr());
        item.setText(3, audit.getVulnerability().getLastDetectedStr());
        item.setText(4, audit.getVulnerability().getTitle());
        item.setText(5, audit.getVulnerability().getSeverity());
        item.setText(6, audit.getVulnerability().getStatus());
        item.setText(7, audit.getVulnerability().getPendingStatus().getStatus());
        item.setText(8, audit.getVulnerability().getApplication().getName());
        item.setText(9, audit.getVulnerability().getOrg().getName());
    }

    private void uiReset() {
    }

    private void uiUpdate() {
    }

    public PreferenceStore getPreferenceStore() {
        return ps;
    }

    public List<Organization> getValidOrganizations() {
        List<Organization> orgs = new ArrayList<Organization>();
        String orgJsonStr = ps.getString(PreferenceConstants.TARGET_ORGS);
        if (orgJsonStr.trim().length() > 0) {
            try {
                List<Organization> orgList = new Gson().fromJson(orgJsonStr, new TypeToken<List<Organization>>() {
                }.getType());
                for (Organization org : orgList) {
                    if (org != null && org.isValid()) {
                        orgs.add(org);
                    }
                }
            } catch (JsonSyntaxException e) {
                return orgs;
            }
        }
        return orgs;
    }

    private void updateAuthorizeBtn() {
        approveBtn.setEnabled(!selectedIdxes.isEmpty());
    }

    private void updateProtectOption() {
        this.auditLogCreatedFilterMap = getAuditLogCreatedDateMap();
        auditLogTermToday.setToolTipText(sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.TODAY)));
        auditLogTermYesterday.setToolTipText(sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.YESTERDAY)));
        auditLogTerm30days.setToolTipText(String.format("%s ～ %s", sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.BEFORE_30_DAYS)),
                sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.TODAY))));
        auditLogTermLastWeek.setToolTipText(String.format("%s ～ %s", sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.LAST_WEEK_START)),
                sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.LAST_WEEK_END))));
        auditLogTermThisWeek.setToolTipText(String.format("%s ～ %s", sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.THIS_WEEK_START)),
                sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.THIS_WEEK_END))));
        auditLogTermHalf1st.setToolTipText(String.format("%s ～ %s", sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_1ST_START)),
                sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_1ST_END))));
        auditLogTermHalf2nd.setToolTipText(String.format("%s ～ %s", sdf.format(this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_2ND_START)),
                sdf.format(auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_2ND_END))));
    }

    private Date[] getFrToDetectedDate() {
        int idx = -1;
        for (Button termBtn : this.auditLogCreatedRadios) {
            if (termBtn.getSelection()) {
                idx = auditLogCreatedRadios.indexOf(termBtn);
                break;
            }
        }
        if (idx < 0) {
            idx = 0;
        }
        Date frDate = null;
        Date toDate = null;
        switch (idx) {
            case 0: // 上半期
                frDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_1ST_START);
                toDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_1ST_END);
                break;
            case 1: // 下半期
                frDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_2ND_START);
                toDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.HALF_2ND_END);
                break;
            case 2: // 30days
                frDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.BEFORE_30_DAYS);
                toDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.TODAY);
                break;
            case 3: // Yesterday
                frDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.YESTERDAY);
                toDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.YESTERDAY);
                break;
            case 4: // Today
                frDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.TODAY);
                toDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.TODAY);
                break;
            case 5: // LastWeek
                frDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.LAST_WEEK_START);
                toDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.LAST_WEEK_END);
                break;
            case 6: // ThisWeek
                frDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.THIS_WEEK_START);
                toDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.THIS_WEEK_END);
                break;
            case 7: // Specify
                if (frCreatedDate == null || toCreatedDate == null) {
                    return new Date[] {};
                }
                return new Date[] { frCreatedDate, toCreatedDate };
            default:
                frDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.BEFORE_30_DAYS);
                toDate = this.auditLogCreatedFilterMap.get(AuditLogCreatedDateFilterEnum.TODAY);
        }
        // Date frDate = Date.from(frLocalDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
        // Calendar cal = Calendar.getInstance();
        // cal.set(toLocalDate.getYear(), toLocalDate.getMonthValue() - 1, toLocalDate.getDayOfMonth(), 23, 59, 59);
        // Date toDate = cal.getTime();
        return new Date[] { frDate, toDate };
    }

    public Map<AuditLogCreatedDateFilterEnum, LocalDate> getAuditLogCreatedDateMapOld() {
        Map<AuditLogCreatedDateFilterEnum, LocalDate> map = new HashMap<AuditLogCreatedDateFilterEnum, LocalDate>();
        LocalDate today = LocalDate.now();

        map.put(AuditLogCreatedDateFilterEnum.TODAY, today);
        map.put(AuditLogCreatedDateFilterEnum.YESTERDAY, today.minusDays(1));
        map.put(AuditLogCreatedDateFilterEnum.BEFORE_30_DAYS, today.minusDays(30));
        LocalDate lastWeekStart = today.with(TemporalAdjusters.previous(DayOfWeek.SUNDAY));
        lastWeekStart = lastWeekStart.minusDays(7 - ps.getInt(PreferenceConstants.START_WEEKDAY));
        if (lastWeekStart.plusDays(7).isAfter(today)) {
            lastWeekStart = lastWeekStart.minusDays(7);
        }
        map.put(AuditLogCreatedDateFilterEnum.LAST_WEEK_START, lastWeekStart);
        map.put(AuditLogCreatedDateFilterEnum.LAST_WEEK_END, lastWeekStart.plusDays(6));
        map.put(AuditLogCreatedDateFilterEnum.THIS_WEEK_START, lastWeekStart.plusDays(7));
        map.put(AuditLogCreatedDateFilterEnum.THIS_WEEK_END, lastWeekStart.plusDays(13));

        int termStartMonth = IntStream.range(0, OtherPreferencePage.MONTHS.length)
                .filter(i -> ps.getString(PreferenceConstants.TERM_START_MONTH).equals(OtherPreferencePage.MONTHS[i])).findFirst().orElse(-1);
        int half_1st_month_s = ++termStartMonth;
        int thisYear = today.getYear();
        int thisMonth = today.getMonthValue();
        // half 1st start
        LocalDate half_1st_month_s_date = null;
        // if (half_1st_month_s + 5 < thisMonth) { // 元の仕様の場合はこのコメント解除
        half_1st_month_s_date = LocalDate.of(thisYear, half_1st_month_s, 1);
        // } else { // 元の仕様の場合はこのコメント解除
        // half_1st_month_s_date = LocalDate.of(thisYear - 1, half_1st_month_s, 1); // 元の仕様の場合はこのコメント解除
        // } // 元の仕様の場合はこのコメント解除
        map.put(AuditLogCreatedDateFilterEnum.HALF_1ST_START, half_1st_month_s_date);
        // half 1st end
        // LocalDate half_1st_month_e_date = half_1st_month_s_date.plusMonths(6).minusDays(1);
        map.put(AuditLogCreatedDateFilterEnum.HALF_1ST_END, half_1st_month_s_date.plusMonths(6).minusDays(1));

        // half 2nd start
        LocalDate half_2nd_month_s_date = half_1st_month_s_date.plusMonths(6);
        // half 2nd end
        LocalDate half_2nd_month_e_date = half_2nd_month_s_date.plusMonths(6).minusDays(1);
        int todayNum = Integer.valueOf(today.format(DateTimeFormatter.ofPattern("yyyyMMdd")));
        int termEndNum = Integer.valueOf(half_2nd_month_e_date.format(DateTimeFormatter.ofPattern("yyyyMMdd")));
        // if (todayNum < termEndNum) { // 元の仕様の場合はこのコメント解除
        // half_2nd_month_s_date = half_2nd_month_s_date.minusYears(1); // 元の仕様の場合はこのコメント解除
        // half_2nd_month_e_date = half_2nd_month_e_date.minusYears(1); // 元の仕様の場合はこのコメント解除
        // } // 元の仕様の場合はこのコメント解除
        map.put(AuditLogCreatedDateFilterEnum.HALF_2ND_START, half_2nd_month_s_date);
        map.put(AuditLogCreatedDateFilterEnum.HALF_2ND_END, half_2nd_month_e_date);
        return map;
    }

    public Map<AuditLogCreatedDateFilterEnum, Date> getAuditLogCreatedDateMap() {
        Map<AuditLogCreatedDateFilterEnum, Date> map = new HashMap<AuditLogCreatedDateFilterEnum, Date>();
        LocalDate today = LocalDate.now();

        map.put(AuditLogCreatedDateFilterEnum.TODAY, Date.from(today.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(AuditLogCreatedDateFilterEnum.YESTERDAY, Date.from(today.minusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(AuditLogCreatedDateFilterEnum.BEFORE_30_DAYS, Date.from(today.minusDays(30).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        LocalDate lastWeekStart = today.with(TemporalAdjusters.previous(DayOfWeek.SUNDAY));
        lastWeekStart = lastWeekStart.minusDays(7 - ps.getInt(PreferenceConstants.START_WEEKDAY));
        if (lastWeekStart.plusDays(7).isAfter(today)) {
            lastWeekStart = lastWeekStart.minusDays(7);
        }
        map.put(AuditLogCreatedDateFilterEnum.LAST_WEEK_START, Date.from(lastWeekStart.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(AuditLogCreatedDateFilterEnum.LAST_WEEK_END, Date.from(lastWeekStart.plusDays(6).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(AuditLogCreatedDateFilterEnum.THIS_WEEK_START, Date.from(lastWeekStart.plusDays(7).atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(AuditLogCreatedDateFilterEnum.THIS_WEEK_END, Date.from(lastWeekStart.plusDays(13).atStartOfDay(ZoneId.systemDefault()).toInstant()));

        int termStartMonth = IntStream.range(0, OtherPreferencePage.MONTHS.length)
                .filter(i -> ps.getString(PreferenceConstants.TERM_START_MONTH).equals(OtherPreferencePage.MONTHS[i])).findFirst().orElse(-1);
        int half_1st_month_s = ++termStartMonth;
        int thisYear = today.getYear();
        // int thisMonth = today.getMonthValue(); // 元の仕様の場合はこのコメント解除
        // half 1st start
        LocalDate half_1st_month_s_date = null;
        // if (half_1st_month_s + 5 < thisMonth) { // 元の仕様の場合はこのコメント解除
        half_1st_month_s_date = LocalDate.of(thisYear, half_1st_month_s, 1);
        // } else { // 元の仕様の場合はこのコメント解除
        // half_1st_month_s_date = LocalDate.of(thisYear - 1, half_1st_month_s, 1); // 元の仕様の場合はこのコメント解除
        // } // 元の仕様の場合はこのコメント解除
        map.put(AuditLogCreatedDateFilterEnum.HALF_1ST_START, Date.from(half_1st_month_s_date.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        // half 1st end
        // LocalDate half_1st_month_e_date = half_1st_month_s_date.plusMonths(6).minusDays(1);
        map.put(AuditLogCreatedDateFilterEnum.HALF_1ST_END, Date.from(half_1st_month_s_date.plusMonths(6).minusDays(1).atStartOfDay(ZoneId.systemDefault()).toInstant()));

        // half 2nd start
        LocalDate half_2nd_month_s_date = half_1st_month_s_date.plusMonths(6);
        // half 2nd end
        LocalDate half_2nd_month_e_date = half_2nd_month_s_date.plusMonths(6).minusDays(1);
        // int todayNum = Integer.valueOf(today.format(DateTimeFormatter.ofPattern("yyyyMMdd"))); // 元の仕様の場合はこのコメント解除
        // int termEndNum = Integer.valueOf(half_2nd_month_e_date.format(DateTimeFormatter.ofPattern("yyyyMMdd"))); // 元の仕様の場合はこのコメント解除
        // if (todayNum < termEndNum) { // 元の仕様の場合はこのコメント解除
        // half_2nd_month_s_date = half_2nd_month_s_date.minusYears(1); // 元の仕様の場合はこのコメント解除
        // half_2nd_month_e_date = half_2nd_month_e_date.minusYears(1); // 元の仕様の場合はこのコメント解除
        // } // 元の仕様の場合はこのコメント解除
        map.put(AuditLogCreatedDateFilterEnum.HALF_2ND_START, Date.from(half_2nd_month_s_date.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        map.put(AuditLogCreatedDateFilterEnum.HALF_2ND_END, Date.from(half_2nd_month_e_date.atStartOfDay(ZoneId.systemDefault()).toInstant()));
        return map;
    }

    public void setWindowTitle() {
        String text = null;
        List<Organization> validOrgs = getValidOrganizations();
        if (!validOrgs.isEmpty()) {
            List<String> orgNameList = new ArrayList<String>();
            for (Organization validOrg : validOrgs) {
                orgNameList.add(validOrg.getName());
            }
            text = String.join(", ", orgNameList);
        }
        boolean isSuperAdmin = ps.getBoolean(PreferenceConstants.IS_SUPERADMIN);
        if (isSuperAdmin) {
            this.shell.setText(String.format(WINDOW_TITLE, "SuperAdmin"));
        } else {
            if (text == null || text.isEmpty()) {
                this.shell.setText(String.format(WINDOW_TITLE, "組織未設定"));
            } else {
                this.shell.setText(String.format(WINDOW_TITLE, text));
            }
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public void propertyChange(PropertyChangeEvent event) {
        if ("auditFilter".equals(event.getPropertyName())) {
            Map<FilterEnum, Set<Filter>> filterMap = (Map<FilterEnum, Set<Filter>>) event.getNewValue();
            pendingVulTable.clearAll();
            pendingVulTable.removeAll();
            filteredAuditLogs.clear();
            selectedIdxes.clear();
            for (Button button : checkBoxList) {
                button.dispose();
            }
            checkBoxList.clear();
            if (isFirstDetectSortDesc) {
                Collections.reverse(auditLogs);
            } else {
                Collections.sort(auditLogs, new Comparator<ItemForVulnerability>() {
                    @Override
                    public int compare(ItemForVulnerability e1, ItemForVulnerability e2) {
                        return e1.getVulnerability().getFirstDetected().compareTo(e2.getVulnerability().getFirstDetected());
                    }
                });
            }
            for (ItemForVulnerability vul : auditLogs) {
                boolean lostFlg = false;
                for (Filter filter : filterMap.get(FilterEnum.RULE_NAME)) {
                    if (vul.getVulnerability().getRuleName().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.SEVERITY)) {
                    if (vul.getVulnerability().getSeverity().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.APP_NAME)) {
                    if (vul.getVulnerability().getApplication().getName().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.ORG_NAME)) {
                    if (vul.getVulnerability().getOrg().getName().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.STATUS)) {
                    if (vul.getVulnerability().getStatus().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                for (Filter filter : filterMap.get(FilterEnum.PENDING_STATUS)) {
                    if (vul.getVulnerability().getPendingStatus().getStatus().equals(filter.getLabel())) {
                        if (!filter.isValid()) {
                            lostFlg |= true;
                        }
                    }
                }
                if (!lostFlg) {
                    addColToPendingVulTable(vul, -1);
                    filteredAuditLogs.add(vul);
                }
            }
            auditLogCount.setText(String.format("%d/%d", filteredAuditLogs.size(), auditLogs.size()));
        } else if ("tsv".equals(event.getPropertyName())) {
            System.out.println("tsv main");
        }

    }

    /**
     * @param listener
     */
    public synchronized void addPropertyChangeListener(PropertyChangeListener listener) {
        this.support.addPropertyChangeListener(listener);
    }

    /**
     * @param listener
     */
    public synchronized void removePropertyChangeListener(PropertyChangeListener listener) {
        this.support.removePropertyChangeListener(listener);
    }
}
