
// Inject64Dlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include "afxeditbrowsectrl.h"


// CInject64Dlg 对话框
class CInject64Dlg : public CDialogEx
{
// 构造
public:
	CInject64Dlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_INJECT64_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	CListBox mProcList;
	CMFCEditBrowseCtrl mDllEditBrowse;
	afx_msg void OnBnClickedOk2();
};
