#include <stdio.h>
#include <Android/log.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdbool.h>

#ifndef BYTE
#define BYTE unsigned char
#endif

#define OPCODEMAXLEN 8      //inline hook所需要的opcodes最大长度

#define LOG_TAG "GSLab"
#define LOGI(fmt, args...) __android_log_print(4, LOG_TAG, fmt, ##args);

extern unsigned long _shellcode_start_s;
extern unsigned long _shellcode_end_s;
extern unsigned long _hookstub_function_addr_s;
extern unsigned long _old_function_addr_s;

//hook点信息
typedef struct tagINLINEHOOKINFO{
    void *pHookAddr;                //hook的地址
    void *pStubShellCodeAddr;            //跳过去的shellcode stub的地址
    void (*onCallBack)(struct pt_regs *);       //回调函数，跳转过去的函数地址
    void ** ppOldFuncAddr;             //shellcode 中存放old function的地址
    BYTE szbyBackupOpcodes[OPCODEMAXLEN];    //原来的opcodes
} INLINE_HOOK_INFO;

bool ChangePageProperty(void *pAddress, size_t size);

extern void * GetModuleBaseAddr(pid_t pid, char* pszModuleName);

bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook);

bool BuildStub(INLINE_HOOK_INFO* pstInlineHook);

bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress);

bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook);

bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook);

extern bool HookArm(INLINE_HOOK_INFO* pstInlineHook);

