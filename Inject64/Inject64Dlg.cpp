
// Inject64Dlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Inject64.h"
#include "Inject64Dlg.h"
#include "afxdialogex.h"
#include <TlHelp32.h>
#include <AtlConv.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CInject64Dlg 对话框



CInject64Dlg::CInject64Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CInject64Dlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CInject64Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, mProcList);
	DDX_Control(pDX, IDC_MFCEDITBROWSE2, mDllEditBrowse);
}

BEGIN_MESSAGE_MAP(CInject64Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CInject64Dlg::OnBnClickedOk)
	ON_BN_CLICKED(IDOK2, &CInject64Dlg::OnBnClickedOk2)
END_MESSAGE_MAP()


// CInject64Dlg 消息处理程序

BOOL CInject64Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码
	mDllEditBrowse.EnableFileBrowseButton(NULL, _T("Dll Files (*.dll)|*.dll|All Files (*.*)|*.*||"));
	CInject64Dlg::OnBnClickedOk();

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CInject64Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CInject64Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CInject64Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

BOOL RemoteLoadLibrary(HANDLE hProcess, LPCSTR lpLibFileName)
{
	PCHAR lpRemoteLibFileName = (PCHAR)VirtualAllocEx(hProcess, NULL, lstrlenA(lpLibFileName) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (lpRemoteLibFileName == NULL)
	{
		return FALSE;
	}
	WriteProcessMemory(hProcess, lpRemoteLibFileName, (void *)lpLibFileName, lstrlenA(lpLibFileName) + 1, NULL);
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(_T("Kernel32")), "LoadLibraryA");
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pfnStartAddr, lpRemoteLibFileName, 0, NULL);
	if (hRemoteThread == NULL)
	{
		return FALSE;
	}
	WaitForSingleObject(hRemoteThread, INFINITE);
	DWORD ExitCode;
	GetExitCodeThread(hRemoteThread, &ExitCode);
	CloseHandle(hRemoteThread);
	VirtualFreeEx(hProcess, lpRemoteLibFileName, 0, MEM_RELEASE);

	return ExitCode;
}

void CInject64Dlg::OnBnClickedOk()
{
	// TODO:  在此添加控件通知处理程序代码
	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);

	mProcList.ResetContent();

	DWORD dwPid = 0;
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return ;

	Process32First(hProcessSnap, &pe32);
	do
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
		BOOL isWow64;
		if (IsWow64Process(hProcess, &isWow64))
		{
			TCHAR szBuf[1024] = { 0 };
			if (isWow64 || sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
			{
				wsprintf(szBuf, _T("%s %4d %s"), _T("(32位)"), pe32.th32ProcessID, pe32.szExeFile);
			}
			else
			{
				wsprintf(szBuf, _T("%s %4d %s"), _T("(64位)"), pe32.th32ProcessID, pe32.szExeFile);
			}
			int count = mProcList.AddString(szBuf);
			mProcList.SetItemData(count, pe32.th32ProcessID);
		}
		CloseHandle(hProcess);
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	//CDialogEx::OnOK();
}


void CInject64Dlg::OnBnClickedOk2()
{
	// TODO:  在此添加控件通知处理程序代码

	USES_CONVERSION;

	//获取选择的dll路径
	CString dllPath;
	mDllEditBrowse.GetWindowText(dllPath);

	//获取选中的进程id,并打开进程
	DWORD pid = mProcList.GetItemData(mProcList.GetCurSel());
	HANDLE hProcess = OpenProcess(\
		PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | SYNCHRONIZE | PROCESS_VM_WRITE | PROCESS_VM_READ, \
		FALSE, pid);
	if (INVALID_HANDLE_VALUE == hProcess || NULL == hProcess)
	{
		AfxMessageBox(_T("打开进程失败!"));
		return;
	}

	if (RemoteLoadLibrary(hProcess, W2A(dllPath)))
	{
		AfxMessageBox(_T("注入成功!"));
	}
	else
	{
		AfxMessageBox(_T("注入失败，检查是否选择了要注入进程和DLL!"));
	}
}
