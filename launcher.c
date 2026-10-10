/*
 * BOBS D2 MENU — Launcher v2.0
 * Dark-themed auth window + System Locker key validation
 * Flow: dark auth prompt -> SL validate -> extract files -> DSE bypass
 *       -> launch CE (nosplash) with CT -> DSE re-enable -> wait -> cleanup
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shlobj.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ===== CONFIG ===== */
#define SL_SYSTEM_ID  "29dc19ec6062665c38f0"
#define SL_VERSION    "1.0"
#define SL_HOST       L"systemlocker.net"
#define SL_PATH       L"/auth/mikros"

#define RES_CE_EXE    101
#define RES_DRIVER    102
#define RES_CT_FILE   103
#define RES_DSE_EXE   104
#define RES_CE_DEPS   105
#define RES_BIN_ICON  106
#define RES_LNV_DRV   107  /* LnvMSRIO.sys  — optional, non-fatal if absent */
#define RES_TS_DRV    108  /* ThrottleStop.sys — optional, non-fatal if absent */

/* CE process name in temp dir — something that won't raise eyebrows */
#define CE_PROC_NAME  "OverlayService.exe"

/* ===== AUTH WINDOW CONFIG ===== */
#define AUTH_W  400
#define AUTH_H  230
#define IDC_EDIT_KEY  1001
#define IDC_BTN_AUTH  1002
#define IDC_BTN_QUIT  1003

#define CLR_BG       RGB(13,  13,  13 )
#define CLR_PANEL    RGB(20,  20,  20 )
#define CLR_CARD     RGB(26,  26,  26 )
#define CLR_ACCENT   RGB(64,  64,  200)
#define CLR_ACCENT2  RGB(90,  90,  220)
#define CLR_TEXT     RGB(238, 238, 238)
#define CLR_DIM      RGB(100, 100, 100)
#define CLR_EDIT_BG  RGB(30,  30,  30 )
#define CLR_BTN_HOV  RGB(80,  80,  220)

#define WM_AUTH_RESULT  (WM_APP + 1)

static char   g_key[128]  = {0};
static char   g_hwid[128] = {0};
static BOOL   g_authOK    = FALSE;
static HWND   g_hWnd      = NULL;
static DWORD  g_cePid     = 0;    /* CE process ID, set after launch */
static BOOL   g_authHov   = FALSE;
static BOOL   g_quitHov   = FALSE;
static BOOL   g_authBusy  = FALSE;
static HBRUSH hBrBg  = NULL, hBrEdit = NULL, hBrCard = NULL;
static HFONT  hFTitle = NULL, hFNorm = NULL, hFSmall = NULL;

typedef struct { char key[128]; char hwid[128]; HWND hWnd; } AuthArgs;
static void url_encode(const char *src, char *dst, size_t dsz);

/* called on bg thread — posts result back so UI thread handles it */
static DWORD WINAPI AuthThread(LPVOID param) {
    AuthArgs *a = (AuthArgs *)param;
    char enc_key[512], enc_hwid[512];
    url_encode(a->key, enc_key, sizeof(enc_key));
    url_encode(a->hwid, enc_hwid, sizeof(enc_hwid));
    char body[1024];
    int blen = snprintf(body, sizeof(body),
        "system=%s&key=%s&hwid=%s&version=%s",
        SL_SYSTEM_ID, enc_key, enc_hwid, SL_VERSION);

    int ok = 0;
    HINTERNET hSes = WinHttpOpen(L"D2Launcher/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (hSes) {
        HINTERNET hCon = WinHttpConnect(hSes, SL_HOST,
            INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (hCon) {
            HINTERNET hReq = WinHttpOpenRequest(hCon, L"POST", SL_PATH,
                NULL, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (hReq) {
                WinHttpAddRequestHeaders(hReq,
                    L"Content-Type: application/x-www-form-urlencoded",
                    (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);
                if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                        (LPVOID)body, (DWORD)blen, (DWORD)blen, 0) &&
                    WinHttpReceiveResponse(hReq, NULL)) {
                    char resp[256] = {0}; DWORD rd = 0;
                    WinHttpReadData(hReq, resp, sizeof(resp)-1, &rd);
                    for (int i=(int)rd-1; i>=0 &&
                            (resp[i]=='\r'||resp[i]=='\n'||resp[i]==' '); i--)
                        resp[i] = '\0';
                    ok = !strcmp(resp, "true") ? 1 : -1;
                    if (ok == -1) {
                        /* pack error string into lParam via heap — freed on recv */
                        const char *msg;
                        if      (!strcmp(resp,"bad key"))     msg="Invalid license key.";
                        else if (!strcmp(resp,"frozen"))      msg="Key frozen.";
                        else if (!strcmp(resp,"banned"))      msg="Key banned.";
                        else if (!strcmp(resp,"expired key")) msg="Key expired.";
                        else if (!strcmp(resp,"hwid"))        msg="HWID mismatch.";
                        else if (!strcmp(resp,"outdated"))    msg="Outdated version.";
                        else if (!strcmp(resp,"paused"))      msg="Auth paused, try again.";
                        else if (!strcmp(resp,"dbe"))         msg="Server error, try again.";
                        else if (!strcmp(resp,"user limit"))  msg="User limit reached.";
                        else                                   msg=resp[0]?resp:"Auth failed.";
                        char *err = (char *)malloc(256);
                        if (err) strncpy(err, msg, 255);
                        PostMessageA(a->hWnd, WM_AUTH_RESULT, 0, (LPARAM)err);
                    } else {
                        PostMessageA(a->hWnd, WM_AUTH_RESULT, 1, 0);
                    }
                } else {
                    char *err = (char *)malloc(256);
                    if (err) strncpy(err,
                        "Cannot reach systemlocker.net.\nCheck connection.", 255);
                    PostMessageA(a->hWnd, WM_AUTH_RESULT, 0, (LPARAM)err);
                }
                WinHttpCloseHandle(hReq);
            }
            WinHttpCloseHandle(hCon);
        }
        WinHttpCloseHandle(hSes);
    } else {
        char *err = (char *)malloc(256);
        if (err) strncpy(err, "WinHTTP init failed.", 255);
        PostMessageA(a->hWnd, WM_AUTH_RESULT, 0, (LPARAM)err);
    }
    free(a);
    return 0;
}

/* ===== URL-ENCODE ===== */
static void url_encode(const char *src, char *dst, size_t dsz) {
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (size_t i = 0; src[i] && o + 4 < dsz; i++) {
        unsigned char c = (unsigned char)src[i];
        if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||
            c=='-'||c=='_'||c=='.'||c=='~') {
            dst[o++] = (char)c;
        } else {
            dst[o++]='%'; dst[o++]=hex[c>>4]; dst[o++]=hex[c&0xF];
        }
    }
    dst[o] = '\0';
}

/* ===== HWID ===== */
static void get_hwid(char *out, size_t sz) {
    HKEY hk = NULL;
    char buf[128] = {0};
    DWORD len = sizeof(buf);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Cryptography", 0,
            KEY_READ|KEY_WOW64_64KEY, &hk) == 0) {
        RegQueryValueExA(hk,"MachineGuid",NULL,NULL,(LPBYTE)buf,&len);
        RegCloseKey(hk);
    }
    if (!buf[0]) {
        DWORD sn = 0;
        GetVolumeInformationA("C:\\",NULL,0,&sn,NULL,NULL,NULL,0);
        snprintf(buf,sizeof(buf),"VOL-%08X",sn);
    }
    strncpy(out,buf,sz-1); out[sz-1]='\0';
}

/* sl_validate is now in AuthThread above */

/* ===== DRAW HELPERS ===== */
static void fillRect(HDC hdc, int x, int y, int w, int h, COLORREF c) {
    RECT r = {x, y, x+w, y+h};
    HBRUSH b = CreateSolidBrush(c);
    FillRect(hdc, &r, b);
    DeleteObject(b);
}
static void drawText(HDC hdc, const char *txt, int x, int y, int w, int h,
                     COLORREF col, HFONT font, UINT flags) {
    RECT r = {x, y, x+w, y+h};
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, col);
    if (font) SelectObject(hdc, font);
    DrawTextA(hdc, txt, -1, &r, flags);
}

/* ===== AUTH WINDOW PROC ===== */
static LRESULT CALLBACK AuthProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hi = GetModuleHandleA(NULL);
        /* Key edit */
        HWND hEd = CreateWindowExA(0,"EDIT","",
            WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL|ES_PASSWORD,
            24, 132, AUTH_W-48, 28, hw,(HMENU)IDC_EDIT_KEY, hi, NULL);
        /* Unset password mask so we can see asterisks but allow paste */
        SendMessageA(hEd, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
        SendMessageA(hEd, WM_SETFONT, (WPARAM)hFNorm, TRUE);
        SendMessageA(hEd, EM_SETLIMITTEXT, 127, 0);

        /* Buttons */
        CreateWindowExA(0,"BUTTON","AUTHENTICATE",
            WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
            24, 174, 220, 30, hw,(HMENU)IDC_BTN_AUTH, hi, NULL);
        CreateWindowExA(0,"BUTTON","CANCEL",
            WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,
            252, 174, AUTH_W-276, 30, hw,(HMENU)IDC_BTN_QUIT, hi, NULL);
        SetFocus(hEd);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hw, &ps);
        /* Background */
        fillRect(dc, 0, 0, AUTH_W, AUTH_H, CLR_BG);
        /* Top accent bar */
        fillRect(dc, 0, 0, AUTH_W, 3, CLR_ACCENT);
        /* Header area */
        fillRect(dc, 0, 3, AUTH_W, 70, CLR_PANEL);
        /* Title */
        drawText(dc, "BOBS D2 MENU", 22, 14, AUTH_W-44, 28,
                 CLR_TEXT, hFTitle, DT_LEFT|DT_SINGLELINE|DT_VCENTER);
        /* Subtitle */
        drawText(dc, "LICENSE AUTHENTICATION  v2.0", 22, 44, AUTH_W-44, 20,
                 CLR_DIM, hFSmall, DT_LEFT|DT_SINGLELINE);
        /* Separator */
        fillRect(dc, 0, 73, AUTH_W, 1, RGB(35,35,35));
        /* "LICENSE KEY" label */
        drawText(dc, "LICENSE KEY", 24, 92, 160, 18,
                 CLR_DIM, hFSmall, DT_LEFT|DT_SINGLELINE);
        /* Edit border highlight */
        fillRect(dc, 22, 130, AUTH_W-44, 32, CLR_ACCENT);
        fillRect(dc, 23, 131, AUTH_W-46, 30, CLR_EDIT_BG);
        EndPaint(hw, &ps);
        return 0;
    }
    case WM_CTLCOLOREDIT: {
        HDC hd = (HDC)wp;
        SetTextColor(hd, CLR_TEXT);
        SetBkColor(hd, CLR_EDIT_BG);
        if (hFNorm) SelectObject(hd, hFNorm);
        return (LRESULT)hBrEdit;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *d = (DRAWITEMSTRUCT*)lp;
        BOOL isAuth = (d->CtlID == IDC_BTN_AUTH);
        BOOL hov    = isAuth ? g_authHov : g_quitHov;
        COLORREF bg = isAuth
            ? (hov ? CLR_ACCENT2 : CLR_ACCENT)
            : (hov ? RGB(45,45,45) : RGB(30,30,30));
        COLORREF tc = isAuth ? CLR_TEXT : CLR_DIM;
        HBRUSH br = CreateSolidBrush(bg);
        FillRect(d->hDC, &d->rcItem, br);
        DeleteObject(br);
        char txt[64]; GetWindowTextA(d->hwndItem, txt, sizeof(txt));
        SetBkMode(d->hDC, TRANSPARENT);
        SetTextColor(d->hDC, tc);
        if (hFNorm) SelectObject(d->hDC, hFNorm);
        DrawTextA(d->hDC, txt, -1, &d->rcItem, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        return TRUE;
    }
    case WM_MOUSEMOVE: {
        int mx = LOWORD(lp), my = HIWORD(lp);
        BOOL ah = (mx>=24 && mx<=244 && my>=174 && my<=204);
        BOOL qh = (mx>=252 && mx<=(AUTH_W-24) && my>=174 && my<=204);
        if (ah != g_authHov || qh != g_quitHov) {
            g_authHov = ah; g_quitHov = qh;
            InvalidateRect(GetDlgItem(hw,IDC_BTN_AUTH),NULL,FALSE);
            InvalidateRect(GetDlgItem(hw,IDC_BTN_QUIT),NULL,FALSE);
        }
        return 0;
    }
    case WM_AUTH_RESULT: {
        g_authBusy = FALSE;
        if (wp) {
            /* success */
            g_authOK = TRUE;
            DestroyWindow(hw);
        } else {
            /* failure — lp is heap string */
            char *err = (char *)lp;
            if (err) {
                MessageBoxA(hw, err, "BOBS D2 MENU — Auth Failed", MB_ICONERROR);
                free(err);
            }
            /* re-enable so user can retry */
            HWND hBtn = GetDlgItem(hw, IDC_BTN_AUTH);
            SetWindowTextA(hBtn, "AUTHENTICATE");
            EnableWindow(hBtn, TRUE);
            hBtn = GetDlgItem(hw, IDC_BTN_QUIT);
            SetWindowTextA(hBtn, "CANCEL");
            EnableWindow(hBtn, TRUE);
            InvalidateRect(GetDlgItem(hw, IDC_BTN_AUTH), NULL, TRUE);
            InvalidateRect(GetDlgItem(hw, IDC_BTN_QUIT), NULL, TRUE);
        }
        return 0;
    }
    case WM_COMMAND:
        if ((LOWORD(wp)==IDC_BTN_AUTH || LOWORD(wp)==IDOK) && !g_authBusy) {
            char buf[128]={0};
            GetDlgItemTextA(hw, IDC_EDIT_KEY, buf, sizeof(buf));
            if (!buf[0]) {
                MessageBoxA(hw, "Please enter your license key.", "BOBS D2 MENU", MB_ICONWARNING);
                return 0;
            }
            strncpy(g_key, buf, sizeof(g_key)-1);
            /* disable buttons and spin up auth thread */
            g_authBusy = TRUE;
            HWND hBtn = GetDlgItem(hw, IDC_BTN_AUTH);
            SetWindowTextA(hBtn, "AUTHENTICATING...");
            EnableWindow(hBtn, FALSE);
            hBtn = GetDlgItem(hw, IDC_BTN_QUIT);
            SetWindowTextA(hBtn, "");
            EnableWindow(hBtn, FALSE);
            InvalidateRect(GetDlgItem(hw, IDC_BTN_AUTH), NULL, TRUE);
            InvalidateRect(GetDlgItem(hw, IDC_BTN_QUIT), NULL, TRUE);

            AuthArgs *a = (AuthArgs *)malloc(sizeof(AuthArgs));
            if (a) {
                strncpy(a->key,  g_key,  sizeof(a->key)-1);
                strncpy(a->hwid, g_hwid, sizeof(a->hwid)-1);
                a->hWnd = hw;
                HANDLE ht = CreateThread(NULL, 0, AuthThread, a, 0, NULL);
                if (ht) CloseHandle(ht);
                else { free(a); g_authBusy = FALSE; }
            }
            return 0;
        }
        if (LOWORD(wp)==IDC_BTN_QUIT || LOWORD(wp)==IDCANCEL) {
            PostQuitMessage(0); return 0;
        }
        break;
    case WM_KEYDOWN:
        if (wp==VK_RETURN) SendMessageA(hw,WM_COMMAND,MAKEWPARAM(IDC_BTN_AUTH,0),0);
        if (wp==VK_ESCAPE) PostQuitMessage(0);
        return 0;
    case WM_NCHITTEST: {
        LRESULT r = DefWindowProcA(hw, msg, wp, lp);
        return (r==HTCLIENT) ? HTCAPTION : r;
    }
    case WM_DESTROY:
        if (!g_authBusy) PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hw, msg, wp, lp);
}

/* ===== PROMPT KEY ===== */
static int prompt_key(HINSTANCE hInst) {
    hBrBg   = CreateSolidBrush(CLR_BG);
    hBrEdit = CreateSolidBrush(CLR_EDIT_BG);
    hBrCard = CreateSolidBrush(CLR_CARD);

    hFTitle = CreateFontA(22,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,
        DEFAULT_PITCH,"Segoe UI");
    hFNorm  = CreateFontA(13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,
        DEFAULT_PITCH,"Segoe UI");
    hFSmall = CreateFontA(11,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,
        DEFAULT_PITCH,"Segoe UI");

    WNDCLASSEXA wc = {0};
    wc.cbSize      = sizeof(wc);
    wc.lpfnWndProc = AuthProc;
    wc.hInstance   = hInst;
    wc.hbrBackground = hBrBg;
    wc.lpszClassName = "D2AuthWnd";
    wc.hCursor     = LoadCursor(NULL, IDC_ARROW);
    RegisterClassExA(&wc);

    int sx = GetSystemMetrics(SM_CXSCREEN);
    int sy = GetSystemMetrics(SM_CYSCREEN);

    g_hWnd = CreateWindowExA(
        WS_EX_TOPMOST,
        "D2AuthWnd","BOBS D2 MENU",
        WS_POPUP|WS_VISIBLE,
        (sx-AUTH_W)/2,(sy-AUTH_H)/2,AUTH_W,AUTH_H,
        NULL,NULL,hInst,NULL);
    if (!g_hWnd) return 0;

    /* Intercept ENTER key from edit to trigger auth */
    HWND hEd = GetDlgItem(g_hWnd, IDC_EDIT_KEY);
    (void)hEd;

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            SendMessageA(g_hWnd, WM_COMMAND, MAKEWPARAM(IDC_BTN_AUTH,0), 0);
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    DeleteObject(hBrBg); DeleteObject(hBrEdit); DeleteObject(hBrCard);
    DeleteObject(hFTitle); DeleteObject(hFNorm); DeleteObject(hFSmall);
    return g_authOK && g_key[0];
}

/* Shared stealth tag — generated once, applied to both driver and CE binary */
static char g_stealth_tag[6];

static void gen_stealth_tag(void) {
    const char *pool = "ABCDEFGHJKLMNPRSTUVWXYZ";
    DWORD seed = GetTickCount() ^ GetCurrentProcessId();
    srand(seed);
    for (int i = 0; i < 5; i++) g_stealth_tag[i] = pool[rand() % 23];
    g_stealth_tag[5] = '\0';
}

/* ===== EXTRACT RESOURCE ===== */
static int extract_res(HINSTANCE hInst, int id, const char *path) {
    HRSRC   hr  = FindResourceA(hInst,MAKEINTRESOURCEA(id),"BIN");
    if (!hr) return 0;
    HGLOBAL hg  = LoadResource(hInst,hr);
    DWORD   sz  = SizeofResource(hInst,hr);
    void   *ptr = LockResource(hg);
    if (!ptr||sz==0) return 0;
    HANDLE hf = CreateFileA(path,GENERIC_WRITE,0,NULL,
        CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if (hf==INVALID_HANDLE_VALUE) return 0;
    DWORD written;
    WriteFile(hf,ptr,sz,&written,NULL);
    CloseHandle(hf);
    return (written==sz);
}

/* Forward declarations for stealth helpers defined later in this file */
static BOOL file_write_all(const char *path, const BYTE *buf, DWORD sz);
static void replace_ansi(BYTE *buf, DWORD sz, const char *old5, const char *new5);
static void replace_wide(BYTE *buf, DWORD sz, const wchar_t *old5, const wchar_t *new5);

/* Extract a driver resource, apply g_stealth_tag patch in-memory BEFORE writing.
   AV never sees the original bytes — the file that hits disk is already stealthed. */
static int extract_res_stealthed(HINSTANCE hInst, int id, const char *path) {
    HRSRC   hr  = FindResourceA(hInst,MAKEINTRESOURCEA(id),"BIN");
    if (!hr) return 0;
    HGLOBAL hg  = LoadResource(hInst,hr);
    DWORD   sz  = SizeofResource(hInst,hr);
    void   *src = LockResource(hg);
    if (!src||sz==0) return 0;
    BYTE *buf = (BYTE*)malloc(sz);
    if (!buf) return 0;
    memcpy(buf,src,sz);

    /* patch PE timestamps (unique hash per run) */
    if (sz >= 0x40) {
        DWORD peOff=*(DWORD*)(buf+0x3C);
        if (peOff+0x60<=sz && *(DWORD*)(buf+peOff)==0x00004550) {
            *(DWORD*)(buf+peOff+8)=GetTickCount()^GetCurrentProcessId()^(DWORD)(ULONG_PTR)buf;
            WORD optMg=*(WORD*)(buf+peOff+0x18);
            DWORD csOff=peOff+0x18+((optMg==0x20B)?0x40:0x40);
            if (csOff+4<=sz) *(DWORD*)(buf+csOff)=0;
            DWORD ddBase=peOff+0x18+((optMg==0x20B)?0x70:0x60);
            DWORD dbgOff=ddBase+6*8;
            if (dbgOff+8<=sz){*(DWORD*)(buf+dbgOff)=0;*(DWORD*)(buf+dbgOff+4)=0;}
        }
    }

    /* replace DBK64/DBK32 device name (ANSI + wide) with g_stealth_tag */
    wchar_t wOld64[6]={L'D',L'B',L'K',L'6',L'4',0};
    wchar_t wOld32[6]={L'D',L'B',L'K',L'3',L'2',0};
    wchar_t wNew[6]; for(int i=0;i<5;i++) wNew[i]=(wchar_t)(unsigned char)g_stealth_tag[i]; wNew[5]=0;
    replace_ansi(buf,sz,"DBK64",g_stealth_tag);
    replace_ansi(buf,sz,"DBK32",g_stealth_tag);
    replace_wide(buf,sz,wOld64,wNew);
    replace_wide(buf,sz,wOld32,wNew);

    BOOL ok = file_write_all(path,buf,sz);
    free(buf);
    return ok?1:0;
}

/* ===== UNZIP ===== */
static int unzip_to_dir(const char *zipPath, const char *destDir) {
    char cmd[2048];
    snprintf(cmd,sizeof(cmd),
        "powershell.exe -NoProfile -NonInteractive -Command \""
        "Add-Type -AN System.IO.Compression.FileSystem;"
        "[IO.Compression.ZipFile]::ExtractToDirectory('%s','%s')\"",
        zipPath,destDir);
    STARTUPINFOA si={0}; si.cb=sizeof(si);
    si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_HIDE;
    PROCESS_INFORMATION pi={0};
    if (!CreateProcessA(NULL,cmd,NULL,NULL,FALSE,
            CREATE_NO_WINDOW,NULL,NULL,&si,&pi)) return 0;
    WaitForSingleObject(pi.hProcess,30000);
    DWORD code=1; GetExitCodeProcess(pi.hProcess,&code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (code==0);
}

/* ===== CE PREP — suppress all first-run dialogs ===== */
static void write_ce_settings(const char *dir) {
    CreateDirectoryA(dir, NULL);
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\cheatengine.settings", dir);
    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    /* Key names match what CE 7.5 actually reads (MainUnit2.pas / formsettingsunit.pas) */
    const char *s =
        "[Main]\r\n"
        "LuaScriptAutomatic=1\r\n"
        "Tutorial=0\r\n"
        "ShowTutorial=0\r\n"
        "TutorialFinished=1\r\n"
        "ShowSplash=0\r\n"
        "FirstRun=0\r\n"
        "Use Kernel Debugger=1\r\n"
        "Use DBVM Debugger=0\r\n"
        "Use Windows Debugger=0\r\n"
        "Use VEH Debugger=0\r\n"
        "Use dbk32 QueryMemoryRegionEx=1\r\n"
        "Use dbk32 ReadWriteProcessMemory=1\r\n"
        "Use dbk32 OpenProcess=1\r\n"
        "Use Processwatcher=1\r\n";
    DWORD wr;
    WriteFile(hf, s, (DWORD)strlen(s), &wr, NULL);
    CloseHandle(hf);
}

static void ce_prep(const char *ceDir) {
    /* Write to both paths: HxD-patched CE uses "Memory Tools", stock CE uses "Cheat Engine" */
    const char *regPaths[] = {
        "Software\\Memory Tools",
        "Software\\Cheat Engine",
        NULL
    };
    for (int p = 0; regPaths[p]; p++) {
        HKEY hk;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, regPaths[p], 0, NULL,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, NULL) != ERROR_SUCCESS)
            continue;
        DWORD one = 1, zero = 0;
        /* Suppress first-run dialogs */
        RegSetValueExA(hk, "LuaScriptAutomatic", 0, REG_DWORD, (BYTE*)&one,  sizeof(one));
        RegSetValueExA(hk, "Tutorial",           0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegSetValueExA(hk, "ShowTutorial",       0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegSetValueExA(hk, "TutorialFinished",   0, REG_DWORD, (BYTE*)&one,  sizeof(one));
        RegSetValueExA(hk, "ShowSplash",         0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegSetValueExA(hk, "FirstRun",           0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        /* Exact key names CE 7.5 reads (verified in MainUnit2.pas ReadBool calls) */
        RegSetValueExA(hk, "Use Kernel Debugger",               0, REG_DWORD, (BYTE*)&one,  sizeof(one));
        RegSetValueExA(hk, "Use DBVM Debugger",                 0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegSetValueExA(hk, "Use Windows Debugger",              0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegSetValueExA(hk, "Use VEH Debugger",                  0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        /* Extra tab — all 4 kernel access checkboxes */
        RegSetValueExA(hk, "Use dbk32 QueryMemoryRegionEx",     0, REG_DWORD, (BYTE*)&one,  sizeof(one));
        RegSetValueExA(hk, "Use dbk32 ReadWriteProcessMemory",  0, REG_DWORD, (BYTE*)&one,  sizeof(one));
        RegSetValueExA(hk, "Use dbk32 OpenProcess",             0, REG_DWORD, (BYTE*)&one,  sizeof(one));
        RegSetValueExA(hk, "Use Processwatcher",                0, REG_DWORD, (BYTE*)&one,  sizeof(one));
        RegCloseKey(hk);
    }
    /* Portable settings file in CE exe dir */
    write_ce_settings(ceDir);
    /* Also write to %APPDATA% for both names */
    char appdata[MAX_PATH], roaming[MAX_PATH];
    if (GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata))) {
        snprintf(roaming, sizeof(roaming), "%s\\Memory Tools", appdata);
        write_ce_settings(roaming);
        snprintf(roaming, sizeof(roaming), "%s\\Cheat Engine", appdata);
        write_ce_settings(roaming);
    }
}

/* ===== DBK64 OVERLAY + CE DIALOG AUTO-DISMISSER — background thread ===== */
static BOOL CALLBACK FindOverlayProc(HWND hwnd, LPARAM lp) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    RECT r; GetWindowRect(hwnd, &r);
    /* frmDriverLoaded: at (0,0), small (<500w <120h), TOPMOST+LAYERED */
    if (r.left != 0 || r.top != 0) return TRUE;
    if ((r.right  - r.left) > 500) return TRUE;
    if ((r.bottom - r.top)  > 120) return TRUE;
    LONG ex = GetWindowLongA(hwnd, GWL_EXSTYLE);
    if ((ex & WS_EX_TOPMOST) && (ex & WS_EX_LAYERED)) {
        *(HWND*)lp = hwnd;
        return FALSE;
    }
    return TRUE;
}

/* Click the first button matching txt inside a dialog window */
static BOOL CALLBACK ClickButtonProc(HWND hChild, LPARAM lp) {
    char cls[64], txt[128];
    GetClassNameA(hChild, cls, sizeof(cls));
    if (_stricmp(cls, "Button") != 0) return TRUE;
    GetWindowTextA(hChild, txt, sizeof(txt));
    const char *want = (const char *)lp;
    /* strip ampersand for shortcut labels like "&Yes" */
    char clean[128]; int ci = 0;
    for (int i = 0; txt[i] && ci < 127; i++)
        if (txt[i] != '&') clean[ci++] = txt[i];
    clean[ci] = '\0';
    if (_stricmp(clean, want) == 0) {
        PostMessageA(hChild, BM_CLICK, 0, 0);
        return FALSE; /* found, stop enum */
    }
    return TRUE;
}

/* Dismiss CE-owned dialog windows: auto-execute Lua, decline tutorial */
static BOOL CALLBACK DismissCEDialog(HWND hwnd, LPARAM lp) {
    (void)lp;
    if (!IsWindowVisible(hwnd)) return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != g_cePid) return TRUE;

    char cls[64], title[256];
    GetClassNameA(hwnd, cls, sizeof(cls));
    GetWindowTextA(hwnd, title, sizeof(title));

    /* Lua execute dialog — click Yes/Execute to run the trainer script */
    if (strstr(title, "Lua") || strstr(title, "lua") ||
        strstr(cls,   "TfrmAutoRun") || strstr(cls, "TfrmScript") ||
        strstr(cls,   "TLuaScript"))
    {
        EnumChildWindows(hwnd, ClickButtonProc, (LPARAM)"Yes");
        EnumChildWindows(hwnd, ClickButtonProc, (LPARAM)"Execute");
        EnumChildWindows(hwnd, ClickButtonProc, (LPARAM)"OK");
        return TRUE;
    }
    /* CE tutorial dialog — dismiss it */
    if (strstr(title, "Tutorial") || strstr(title, "tutorial") ||
        strstr(cls,   "TfrmTutorial") || strstr(cls, "Tutorial"))
    {
        EnumChildWindows(hwnd, ClickButtonProc, (LPARAM)"No");
        EnumChildWindows(hwnd, ClickButtonProc, (LPARAM)"Cancel");
        PostMessageA(hwnd, WM_CLOSE, 0, 0);
        return TRUE;
    }
    /* Generic small dialog from CE (MessageDlg etc.) — check for "Do you want" Lua prompt */
    if (strstr(title, "Do you want") || strstr(title, "script") ||
        strstr(title, "Script") || strstr(title, "Cheat Engine"))
    {
        /* If it has a Yes button it's probably the Lua prompt */
        EnumChildWindows(hwnd, ClickButtonProc, (LPARAM)"Yes");
        return TRUE;
    }
    return TRUE;
}

/* Hide the CE main form so only the trainer overlay (from Lua) is visible.
   CE's main form is a Delphi TForm — class starts with "Tfr" or "TMe".
   We hide large top-level windows owned by the CE process. */
static BOOL CALLBACK HideCEMainWnd(HWND hwnd, LPARAM lp) {
    (void)lp;
    if (!IsWindowVisible(hwnd)) return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != g_cePid) return TRUE;
    char cls[64] = {0};
    GetClassNameA(hwnd, cls, sizeof(cls));
    if (strncmp(cls, "Tfr", 3) == 0 || strncmp(cls, "TMe", 3) == 0 ||
        strncmp(cls, "TfrmMain", 8) == 0) {
        RECT r; GetWindowRect(hwnd, &r);
        if ((r.right - r.left) > 300 && (r.bottom - r.top) > 200)
            ShowWindow(hwnd, SW_HIDE);
    }
    return TRUE;
}

static DWORD WINAPI SuppressDriverOverlay(LPVOID param) {
    (void)param;
    /* Poll for 12 seconds — CE + CT load can take a few seconds on slow PCs */
    for (int i = 0; i < 120; i++) {
        Sleep(100);

        /* DBK64 loaded overlay */
        HWND hw = FindWindowA("TfrmDriverLoaded", NULL);
        if (!hw) {
            HWND found = NULL;
            EnumWindows(FindOverlayProc, (LPARAM)&found);
            hw = found;
        }
        if (hw) PostMessageA(hw, WM_CLOSE, 0, 0);

        /* CE dialog auto-clicker — runs every tick while CE is alive */
        if (g_cePid) EnumWindows(DismissCEDialog, 0);

        /* Hide CE main window — keep running for the first 6 seconds so it
           catches the window even if CE takes a moment to create it */
        if (g_cePid && i < 60) EnumWindows(HideCEMainWnd, 0);
    }
    return 0;
}

/* ===== LAUNCH CE (SW_SHOWMINNOACTIVE so it doesn't flash full-screen) ===== */
static HANDLE run_ce(const char *exe, const char *args) {
    char cmd[MAX_PATH*2];
    snprintf(cmd, sizeof(cmd), "\"%s\" %s", exe, args);
    STARTUPINFOA si = {0}; si.cb = sizeof(si);
    si.dwFlags    = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWMINNOACTIVE;  /* start as minimized taskbar icon */
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return INVALID_HANDLE_VALUE;
    g_cePid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

/* ===== LAUNCH ===== */
static HANDLE run(const char *exe, const char *args, int hidden, int wait) {
    char cmd[MAX_PATH*2];
    if (args&&args[0]) snprintf(cmd,sizeof(cmd),"\"%s\" %s",exe,args);
    else               snprintf(cmd,sizeof(cmd),"\"%s\"",exe);
    STARTUPINFOA si={0}; si.cb=sizeof(si);
    if (hidden){si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;}
    PROCESS_INFORMATION pi={0};
    if (!CreateProcessA(NULL,cmd,NULL,NULL,FALSE,
            hidden?CREATE_NO_WINDOW:0,NULL,NULL,&si,&pi))
        return INVALID_HANDLE_VALUE;
    if (wait){WaitForSingleObject(pi.hProcess,30000);
              CloseHandle(pi.hProcess);CloseHandle(pi.hThread);
              return INVALID_HANDLE_VALUE;}
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

/* ===== DSE RUNNER =====
   reenable=0: runs "dsepatch.exe -off" — disables DSE, saves state, exits 0.
   reenable=1: runs "dsepatch.exe -on"  — restores DSE from saved state, exits 0.
   Exit codes: 0=success, 1=failed, 2=HVCI blocked (bcdedit set, needs reboot). */
static DWORD run_dse(const char *exe, int reenable) {
    char cmd[MAX_PATH + 8];
    snprintf(cmd, sizeof(cmd), "\"%s\" %s", exe, reenable ? "-on" : "-off");

    STARTUPINFOA si = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0xFFFFFFFF;

    WaitForSingleObject(pi.hProcess, 20000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code;
}

/* ===== DRIVER BLOCKER CHECKS ===== */

/* Query live HVCI state from the kernel — registry config alone is not reliable.
   EnableVirtualizationBasedSecurity=1 means VBS is *configured*, not necessarily running.
   SystemCodeIntegrityInformation reports what's actually enforced right now. */
typedef struct { ULONG Length; ULONG CodeIntegrityOptions; } SCI_INFO;
#define SystemCodeIntegrityInformation 103
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED 0x400
#define CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED  0x800

static BOOL is_hvci_running(void) {
    typedef LONG (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                              "NtQuerySystemInformation");
    if (!NtQSI) return FALSE;
    SCI_INFO sci = { sizeof(sci), 0 };
    ULONG ret = 0;
    if (NtQSI(SystemCodeIntegrityInformation, &sci, sizeof(sci), &ret) != 0)
        return FALSE;
    return (sci.CodeIntegrityOptions &
            (CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED | CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED)) != 0;
}

static BOOL is_hvci_enabled(void) {
    /* First check live state — if hypervisor isn't actually running, skip the block */
    if (!is_hvci_running()) return FALSE;

    /* Hypervisor IS running; also confirm the registry HVCI key is set (belt+suspenders) */
    HKEY hk; DWORD val = 0, sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\"
            "Scenarios\\HypervisorEnforcedCodeIntegrity",
            0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
        RegQueryValueExA(hk, "Enabled", NULL, NULL, (BYTE*)&val, &sz);
        RegCloseKey(hk);
    }
    return val != 0;
}

/* 0=off, 1=eval, 2=enforcing */
static DWORD get_sac_state(void) {
    HKEY hk; DWORD val = 0, sz = sizeof(val);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\CI\\Policy",
            0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
        RegQueryValueExA(hk, "VerifiedAndReputablePolicyState",
                         NULL, NULL, (BYTE*)&val, &sz);
        RegCloseKey(hk);
    }
    return val;
}

/* Disable Vulnerable Driver Blocklist (Win11 22H2+ has this on by default,
   separate from HVCI — blocks specific exploitable drivers at load time).
   Registry change takes full effect after restart; may help immediately if
   the WDAC policy isn't also enforcing it. */
static void disable_vdb(void) {
    DWORD zero = 0;
    HKEY hk;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "VulnerableDriverBlocklistEnable", 0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegCloseKey(hk);
    }
}

/* Disable Defender real-time protection via policy key.
   Policy keys bypass Tamper Protection on non-domain PCs and take effect
   within seconds (Defender polls for policy changes). This prevents Defender
   from killing DSE.exe or the vulnerable driver it uses. */
static void disable_defender_rt(void) {
    DWORD one = 1;
    HKEY hk;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "DisableRealtimeMonitoring",  0, REG_DWORD, (BYTE*)&one, sizeof(one));
        RegSetValueExA(hk, "DisableBehaviorMonitoring",  0, REG_DWORD, (BYTE*)&one, sizeof(one));
        RegSetValueExA(hk, "DisableOnAccessProtection",  0, REG_DWORD, (BYTE*)&one, sizeof(one));
        RegCloseKey(hk);
    }
}

static void restore_defender_rt(void) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
            0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegDeleteValueA(hk, "DisableRealtimeMonitoring");
        RegDeleteValueA(hk, "DisableBehaviorMonitoring");
        RegDeleteValueA(hk, "DisableOnAccessProtection");
        RegCloseKey(hk);
    }
}

/* Auto-disable HVCI + VBS in registry — user still needs to restart once */
static void try_disable_hvci(void) {
    DWORD zero = 0;
    HKEY hk;
    /* HVCI scenario */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\"
            "Scenarios\\HypervisorEnforcedCodeIntegrity",
            0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "Enabled",            0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegSetValueExA(hk, "WasEnabledBy",       0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegCloseKey(hk);
    }
    /* DeviceGuard VBS — disable the whole stack so HVCI can't re-arm on restart */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "EnableVirtualizationBasedSecurity",  0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegSetValueExA(hk, "RequirePlatformSecurityFeatures",    0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegSetValueExA(hk, "HypervisorEnforcedCodeIntegrity",    0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegCloseKey(hk);
    }
    /* Also disable VDB while we're here — needed after restart too */
    disable_vdb();
}

static BOOL is_win11_or_later(void) {
    typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOEXW *);
    RtlGetVersion_t fn = (RtlGetVersion_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (!fn) return FALSE;
    OSVERSIONINFOEXW ov = {0}; ov.dwOSVersionInfoSize = sizeof(ov);
    fn(&ov);
    return ov.dwBuildNumber >= 22000;  /* Win11 starts at build 22000 */
}

/* Show driver blocker error and return TRUE if a known blocker is detected */
static BOOL check_driver_blockers(void) {
    if (is_hvci_enabled()) {
        /* Auto-set the registry so after one restart it's done */
        try_disable_hvci();
        MessageBoxA(NULL,
            "Memory Integrity (HVCI) is ON — driver cannot load.\n\n"
            "The launcher has already turned it off in the registry.\n"
            "You just need to RESTART your PC once, then run this again.\n\n"
            "To confirm it's off after restart:\n"
            "  Windows Security -> Device Security -> Core isolation\n"
            "  'Memory integrity' should show OFF.\n\n"
            "If it keeps turning back ON your PC may be domain-managed\n"
            "(work/school policy). On a personal PC one restart is enough.",
            "BOBS D2 MENU - Restart Required", MB_ICONWARNING);
        return TRUE;
    }
    /* Smart App Control only exists on Win11 — skip on Win10 */
    if (is_win11_or_later()) {
        DWORD sac = get_sac_state();
        if (sac >= 1) {
            MessageBoxA(NULL,
                "Cannot load driver: Smart App Control is active.\n\n"
                "Smart App Control (SAC) blocks unsigned kernel code even when\n"
                "Windows Defender is turned off.\n\n"
                "To fix:\n"
                "  Windows Security -> App & Browser Control\n"
                "  -> Smart App Control -> set to OFF\n"
                "  Then restart your PC and try again.\n\n"
                "Note: Turning off SAC cannot be undone without resetting Windows.",
                "BOBS D2 MENU - Driver Error", MB_ICONERROR);
            return TRUE;
        }
    }
    return FALSE;
}

/* ===== STEALTH: DRIVER + CE BINARY SIGNATURE PATCH ===== */
static BOOL file_read_all(const char *path, BYTE **out, DWORD *sz) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    *sz = GetFileSize(h, NULL);
    if (*sz == INVALID_FILE_SIZE || *sz == 0) { CloseHandle(h); return FALSE; }
    *out = (BYTE*)malloc(*sz);
    if (!*out) { CloseHandle(h); return FALSE; }
    DWORD rd = 0; ReadFile(h, *out, *sz, &rd, NULL);
    CloseHandle(h);
    *sz = rd;
    return rd > 0;
}

static BOOL file_write_all(const char *path, const BYTE *buf, DWORD sz) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD wr = 0; WriteFile(h, buf, sz, &wr, NULL);
    CloseHandle(h);
    return wr == sz;
}

static void patch_pe_timestamps(BYTE *buf, DWORD sz) {
    if (sz < 0x40) return;
    DWORD peOff = *(DWORD*)(buf + 0x3C);
    if (peOff + 0x60 > sz) return;
    if (*(DWORD*)(buf + peOff) != 0x00004550) return;
    /* Randomize TimeDateStamp in COFF header */
    *(DWORD*)(buf + peOff + 8) = GetTickCount() ^ GetCurrentProcessId() ^ (DWORD)(ULONG_PTR)buf;
    /* Zero CheckSum in Optional Header (+0x40 from COFF = PE+0x58) */
    WORD optMagic = *(WORD*)(buf + peOff + 0x18);
    DWORD csOff = peOff + 0x18 + ((optMagic == 0x20B) ? 0x40 : 0x40);
    if (csOff + 4 <= sz) *(DWORD*)(buf + csOff) = 0;
    /* Zero debug data directory (entry 6, each 8 bytes) */
    DWORD ddBase = peOff + 0x18 + ((optMagic == 0x20B) ? 0x70 : 0x60);
    DWORD dbgOff = ddBase + 6 * 8;
    if (dbgOff + 8 <= sz) { *(DWORD*)(buf + dbgOff) = 0; *(DWORD*)(buf + dbgOff + 4) = 0; }
}

/* Replace every occurrence of 5-byte ANSI str in raw buf */
static void replace_ansi(BYTE *buf, DWORD sz, const char *old5, const char *new5) {
    for (DWORD i = 0; i + 5 <= sz; i++)
        if (memcmp(buf + i, old5, 5) == 0) { memcpy(buf + i, new5, 5); i += 4; }
}

/* Replace every occurrence of 5-wchar (10-byte) UTF-16LE string in raw buf */
static void replace_wide(BYTE *buf, DWORD sz, const wchar_t *old5, const wchar_t *new5) {
    for (DWORD i = 0; i + 10 <= sz; i++)
        if (memcmp(buf + i, old5, 10) == 0) { memcpy(buf + i, new5, 10); i += 9; }
}

/* Patch DBK device name strings in the CE binary using g_stealth_tag.
   Driver is already patched in-memory by extract_res_stealthed — no disk read-back. */
static void stealth_patch(const char *cePath) {
    wchar_t wOld64[6]={L'D',L'B',L'K',L'6',L'4',0};
    wchar_t wOld32[6]={L'D',L'B',L'K',L'3',L'2',0};
    wchar_t wNew[6]; for(int i=0;i<5;i++) wNew[i]=(wchar_t)(unsigned char)g_stealth_tag[i]; wNew[5]=0;
    BYTE *buf=NULL; DWORD sz=0;
    if (!file_read_all(cePath,&buf,&sz)) return;
    replace_ansi(buf,sz,"DBK64",g_stealth_tag);
    replace_ansi(buf,sz,"DBK32",g_stealth_tag);
    replace_wide(buf,sz,wOld64,wNew);
    replace_wide(buf,sz,wOld32,wNew);
    file_write_all(cePath,buf,sz);
    free(buf);
}

/* ===== BASIC HWID SPOOF — rotate MachineGuid before game launch ===== */
static char g_origGuid[64] = {0};

static void spoof_hwid(void) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WRITE, &hk) != ERROR_SUCCESS) return;
    DWORD sz = sizeof(g_origGuid);
    RegQueryValueExA(hk, "MachineGuid", NULL, NULL, (BYTE*)g_origGuid, &sz);
    /* Generate random GUID using same seed as stealth_patch */
    DWORD r[4]; for (int i=0;i<4;i++) r[i] = GetTickCount()^(GetCurrentProcessId()<<(i*7))^(DWORD)rand();
    char ng[64];
    snprintf(ng, sizeof(ng), "%08lx-%04lx-%04lx-%04lx-%08lx%04lx",
             r[0], r[1]&0xFFFF, (r[1]>>16)&0x0FFF|0x4000,
             (r[2]&0x3FFF)|0x8000, r[3], (r[2]>>16)&0xFFFF);
    RegSetValueExA(hk, "MachineGuid", 0, REG_SZ, (BYTE*)ng, (DWORD)strlen(ng)+1);
    RegCloseKey(hk);
}

static void restore_hwid(void) {
    if (!g_origGuid[0]) return;
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_WRITE, &hk) != ERROR_SUCCESS) return;
    RegSetValueExA(hk, "MachineGuid", 0, REG_SZ,
                   (BYTE*)g_origGuid, (DWORD)strlen(g_origGuid)+1);
    RegCloseKey(hk);
}

/* ===== KILL PROCESS BY NAME ===== */
static void kill_by_name(const wchar_t *procName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procName) == 0) {
                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

/* ===== ICON PATCH — replace all RT_ICON/RT_GROUP_ICON in exePath with icoPath ===== */
static void patch_exe_icon(const char *exePath, const char *icoPath) {
    HANDLE hFile = CreateFileA(icoPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(hFile, NULL);
    if (sz == INVALID_FILE_SIZE || sz < 6) { CloseHandle(hFile); return; }
    BYTE *ico = (BYTE*)malloc(sz);
    if (!ico) { CloseHandle(hFile); return; }
    DWORD rd = 0;
    ReadFile(hFile, ico, sz, &rd, NULL);
    CloseHandle(hFile);
    if (rd < 6) { free(ico); return; }

    WORD count = *(WORD*)(ico + 4);
    if (count == 0 || count > 20) { free(ico); return; }

    /* GRPICONDIRENTRY is 14 bytes: width(1)+height(1)+clrCount(1)+res(1)+planes(2)+bitCnt(2)+bytes(4)+id(2) */
    DWORD grpSize = 6 + (DWORD)count * 14;
    BYTE *grp = (BYTE*)calloc(1, grpSize);
    if (!grp) { free(ico); return; }
    memcpy(grp, ico, 6); /* copy ICONDIR header (reserved+type+count) */

    HANDLE hUpd = BeginUpdateResourceA(exePath, FALSE);
    if (!hUpd) { free(ico); free(grp); return; }

    BYTE *entries = ico + 6;
    for (WORD i = 0; i < count; i++) {
        BYTE  *e         = entries + (DWORD)i * 16; /* ICONDIRENTRY is 16 bytes */
        DWORD bytesInRes = *(DWORD*)(e + 8);
        DWORD imgOffset  = *(DWORD*)(e + 12);
        WORD  id         = (WORD)(i + 1);

        UpdateResourceA(hUpd, (LPCSTR)RT_ICON, MAKEINTRESOURCEA(id),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                        ico + imgOffset, bytesInRes);

        BYTE *ge = grp + 6 + (DWORD)i * 14;
        memcpy(ge, e, 8);               /* width, height, colorCount, reserved, planes, bitCount */
        *(DWORD*)(ge + 8) = bytesInRes;
        *(WORD*)(ge + 12) = id;
    }

    UpdateResourceA(hUpd, (LPCSTR)RT_GROUP_ICON, MAKEINTRESOURCEA(1),
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                    grp, grpSize);

    EndUpdateResource(hUpd, FALSE);
    free(ico); free(grp);
}


/* ===== LOCK DIR — hide and restrict temp dir to current user only ===== */
static void lock_dir(const char *dir) {
    SetFileAttributesA(dir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return;
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
    TOKEN_USER *tu = (TOKEN_USER*)malloc(sz);
    if (!tu) { CloseHandle(hToken); return; }
    if (!GetTokenInformation(hToken, TokenUser, tu, sz, &sz)) {
        free(tu); CloseHandle(hToken); return;
    }
    CloseHandle(hToken);

    EXPLICIT_ACCESS_A ea = {0};
    ea.grfAccessPermissions    = GENERIC_ALL;
    ea.grfAccessMode           = SET_ACCESS;
    ea.grfInheritance          = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm     = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType     = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName       = (LPSTR)tu->User.Sid;

    PACL pACL = NULL;
    if (SetEntriesInAclA(1, &ea, NULL, &pACL) == ERROR_SUCCESS) {
        SetNamedSecurityInfoA((LPSTR)dir, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            NULL, NULL, pACL, NULL);
        LocalFree(pACL);
    }
    free(tu);
}

/* ===== CLEANUP ===== */
static void cleanup_dir(const char *dir) {
    char pattern[MAX_PATH];
    snprintf(pattern,sizeof(pattern),"%s\\*",dir);
    WIN32_FIND_DATAA fd;
    HANDLE hf=FindFirstFileA(pattern,&fd);
    if (hf==INVALID_HANDLE_VALUE){RemoveDirectoryA(dir);return;}
    do {
        if (!strcmp(fd.cFileName,".")||!strcmp(fd.cFileName,"..")) continue;
        char full[MAX_PATH];
        snprintf(full,sizeof(full),"%s\\%s",dir,fd.cFileName);
        if (fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) cleanup_dir(full);
        else DeleteFileA(full);
    } while (FindNextFileA(hf,&fd));
    FindClose(hf);
    RemoveDirectoryA(dir);
}

/* ===== MAIN ===== */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lp, int nShow) {
    (void)hPrev; (void)lp; (void)nShow;

    get_hwid(g_hwid, sizeof(g_hwid));

    if (!prompt_key(hInst)) return 0;

    /* Use AppData\Microsoft\Windows\ — blends in with Windows components */
    char base[MAX_PATH], dir[MAX_PATH];
    if (!GetEnvironmentVariableA("LOCALAPPDATA", base, sizeof(base)))
        GetTempPathA(sizeof(base), base);
    /* strip any trailing backslash from GetTempPath */
    { size_t _n = strlen(base); if (_n && base[_n-1]=='\\') base[_n-1]='\0'; }
    snprintf(dir, sizeof(dir), "%s\\Microsoft\\Windows\\Srv%08X", base, GetTickCount());
    if (!CreateDirectoryA(dir, NULL)) {
        /* parent may not exist — ensure %LOCALAPPDATA%\Microsoft\Windows\ */
        char par1[MAX_PATH], par2[MAX_PATH];
        snprintf(par1, sizeof(par1), "%s\\Microsoft", base);
        snprintf(par2, sizeof(par2), "%s\\Microsoft\\Windows", base);
        CreateDirectoryA(par1, NULL);
        CreateDirectoryA(par2, NULL);
        if (!CreateDirectoryA(dir, NULL)) {
            MessageBoxA(NULL,"Failed to create temp directory.","BOBS D2 MENU",MB_ICONERROR);
            return 1;
        }
    }
    lock_dir(dir);  /* hide + restrict ACL to current user only */

    char ce[MAX_PATH], drv[MAX_PATH], ct[MAX_PATH], dse[MAX_PATH],
         deps[MAX_PATH], ico[MAX_PATH], lnv[MAX_PATH], ts[MAX_PATH];
    snprintf(ce,   sizeof(ce),   "%s\\" CE_PROC_NAME,     dir);
    snprintf(drv,  sizeof(drv),  "%s\\WinDiag64.sys",     dir);
    snprintf(ct,   sizeof(ct),   "%s\\cache.ct",          dir);  /* innocuous name */
    snprintf(dse,  sizeof(dse),  "%s\\dsepatch.exe",      dir);
    snprintf(deps, sizeof(deps), "%s\\ce_deps.zip",       dir);
    snprintf(ico,  sizeof(ico),  "%s\\icon.ico",          dir);
    snprintf(lnv,  sizeof(lnv),  "%s\\LnvMSRIO.sys",     dir);
    snprintf(ts,   sizeof(ts),   "%s\\ThrottleStop.sys",  dir);

    /* Generate stealth tag BEFORE any extraction — driver is patched in-memory,
       so AV never sees the original bytes land on disk. */
    gen_stealth_tag();

    #define CHK(call, label) do { if (!(call)) { \
        char _em[256]; snprintf(_em,sizeof(_em),"Step failed: %s\nError: %lu",label,GetLastError()); \
        MessageBoxA(NULL,_em,"BOBS D2 MENU",MB_ICONERROR); goto clean; } } while(0)

    CHK(extract_res(hInst,RES_CE_EXE, ce),              "extract " CE_PROC_NAME);
    CHK(extract_res_stealthed(hInst,RES_DRIVER, drv),   "extract WinDiag64.sys");
    CHK(extract_res(hInst,RES_CT_FILE, ct),   "extract trainer.ct");
    CHK(extract_res(hInst,RES_DSE_EXE, dse),  "extract dsepatch.exe");
    CHK(extract_res(hInst,RES_CE_DEPS, deps), "extract ce_deps.zip");
    extract_res(hInst, RES_BIN_ICON, ico);    /* icon — best effort, non-fatal */
    /* LNV/TS companion drivers for Win11 23H2+ — non-fatal if resources not yet embedded */
    extract_res(hInst, RES_LNV_DRV, lnv);
    extract_res(hInst, RES_TS_DRV,  ts);
    patch_exe_icon(ce, ico);                  /* replace CE icon in extracted binary */
    /* icon.ico stays on disk — Lua loads it for the trainer window icon */
    CHK(unzip_to_dir(deps, dir),              "unzip ce_deps.zip");
    DeleteFileA(deps);

    /* Patch DBK device name strings in CE binary (driver already patched in extract_res_stealthed). */
    stealth_patch(ce);

    /* Pre-flight: check for HVCI / Smart App Control before wasting time on DSE bypass */
    if (check_driver_blockers()) goto clean;

    /* Rotate MachineGuid before D2/BE ever runs — restored on exit */
    spoof_hwid();

    /* Disable Defender real-time + VDB before touching the kernel driver.
       Defender kills DSE.exe mid-patch on Win11; VDB blocks the vulnerable
       driver it uses. Both are restored in cleanup. */
    disable_defender_rt();
    disable_vdb();
    Sleep(1200);  /* give Defender ~1200ms to read the policy change before touching kernel */

    {
        DWORD dseErr = run_dse(dse, 0);
        if (dseErr == 3) {
            /* WDAC base policy permanently blocks RTCore64 — rebooting does nothing.
               Happens on Win11 22H2+ where RTCore64 hash is in the immutable WDAC
               blocklist, independent of VDB registry or bcdedit settings. */
            MessageBoxA(NULL,
                "Windows is permanently blocking the driver on this build.\n\n"
                "This is caused by the Windows Defender Application Control (WDAC)\n"
                "base policy — it cannot be overridden by registry or bcdedit,\n"
                "and rebooting will NOT fix it.\n\n"
                "To fix:\n"
                "  1. Windows Security -> Device Security -> Core isolation\n"
                "     Turn OFF 'Memory integrity' if shown ON, then restart\n"
                "  2. In PowerShell (admin):\n"
                "       bcdedit /set hypervisorlaunchtype off\n"
                "       bcdedit /set vsmlaunchtype off\n"
                "     Then restart and run again\n"
                "  3. If still blocked: Windows 11 24H2+ has WDAC enforced via\n"
                "     Secure Boot policy — you may need to add a WDAC exception\n"
                "     or use a Windows version without this policy.",
                "BOBS D2 MENU - Driver Permanently Blocked", MB_ICONERROR);
            goto clean;
        }
        if (dseErr == 2) {
            /* VDB/HVCI registry fix was applied by dsepatch — needs one reboot.
               Auto-reboot with a 10-second countdown so the user doesn't have to
               do anything manually; SE_SHUTDOWN_NAME is already held (admin). */
            HANDLE hTok = NULL;
            if (OpenProcessToken(GetCurrentProcess(),
                                 TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
                TOKEN_PRIVILEGES tp = {1};
                LookupPrivilegeValueA(NULL, "SeShutdownPrivilege",
                                      &tp.Privileges[0].Luid);
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hTok, FALSE, &tp, 0, NULL, NULL);
                CloseHandle(hTok);
            }
            int choice = MessageBoxA(NULL,
                "A one-time driver compatibility fix was applied.\n\n"
                "Your PC needs to restart once to take effect.\n"
                "After that it will work every session with no restart needed.\n\n"
                "Click OK to reboot now (10 sec), or Cancel to reboot manually.",
                "BOBS D2 MENU - Reboot Required", MB_OKCANCEL | MB_ICONINFORMATION);
            if (choice == IDOK)
                InitiateSystemShutdownExA(NULL,
                    "BOBS D2 MENU applied a driver fix. Rebooting...",
                    10, FALSE, TRUE, SHTDN_REASON_MAJOR_APPLICATION);
            goto clean;
        }
        if (dseErr != 0) {
            /* codes 2/3 = hard blocks (reboot needed / WDAC permanent) — already handled above */
            /* code 1 = DSE patch failed but not HVCI/SAC blocked; proceed anyway.
               The CT's Lua autoDSEToggleAsync will retry on dbk_initialize. */
            (void)dseErr;
        }
    }
    Sleep(400);

    ce_prep(dir);

    char ctArg[MAX_PATH+64];
    snprintf(ctArg, sizeof(ctArg), "--load \"%s\" --nosplash", ct);
    HANDLE hCE = run_ce(ce, ctArg);
    { HANDLE hSup = CreateThread(NULL, 0, SuppressDriverOverlay, NULL, 0, NULL);
      if (hSup) CloseHandle(hSup); }

    Sleep(4000);
    DeleteFileA(ct);
    /* mode 1: reenable — new instance, answers disable+reenable prompts, exits clean */
    run_dse(dse, 1);
    /* Restore Defender NOW — before D2 launches so BattleEye sees AV running */
    restore_defender_rt();

    if (hCE != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(hCE, INFINITE);
        CloseHandle(hCE);
    }

clean:
    kill_by_name(L"dsepatch.exe");
    restore_hwid();
    restore_defender_rt();  /* safety net in case we goto clean before the normal restore */
    Sleep(800);
    cleanup_dir(dir);
    return 0;
}
