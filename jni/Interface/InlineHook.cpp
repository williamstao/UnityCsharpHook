#include <vector>
#include <sys/system_properties.h>
#include <pthread.h>

#include <string>

#include <unistd.h>  
#include <sys/stat.h>  
#include <sys/time.h>  
#include <stdlib.h>  
#include <fcntl.h>  

extern "C"
{
    #include "Ihook.h"
}

void LibMain() __attribute__((constructor));
int g_monoBase = 0;
int g_gameCoreBase = 0;
typedef std::vector<INLINE_HOOK_INFO*> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;     //管理HOOK点
/**
 * 对外inline hook接口，负责管理inline hook信息
 * @param  pHookAddr     要hook的地址
 * @param  onCallBack    要插入的回调函数
 * @return               inlinehook是否设置成功（已经设置过，重复设置返回false）
 */
bool InlineHook(void *pHookAddr, void (*onCallBack)(struct pt_regs *))
{
    bool bRet = false;

    if(pHookAddr == NULL || onCallBack == NULL)
    {
        return bRet;
    }

    INLINE_HOOK_INFO* pstInlineHook = new INLINE_HOOK_INFO();
    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;
    
    //DEMO只很对ARM指令进行演示，更通用这里需要判断区分THUMB等指令
    if(HookArm(pstInlineHook) == false)
    {
        LOGI("HookArm fail.");
        delete pstInlineHook;
        return bRet;
    }
    
    gs_vecInlineHookInfo.push_back(pstInlineHook);
    return true;
}

/**
 * 对外接口，用于取消inline hook
 * @param  pHookAddr 要取消inline hook的位置
 * @return           是否取消成功（不存在返回取消失败）
 */
bool UnInlineHook(void *pHookAddr)
{
    bool bRet = false;

    if(pHookAddr == NULL)
    {
        return bRet;
    }

    InlineHookInfoPVec::iterator itr = gs_vecInlineHookInfo.begin();
    InlineHookInfoPVec::iterator itrend = gs_vecInlineHookInfo.end();

    for (; itr != itrend; ++itr)
    {
        if (pHookAddr == (*itr)->pHookAddr)
        {
            INLINE_HOOK_INFO* pTargetInlineHookInfo = (*itr);

            gs_vecInlineHookInfo.erase(itr);
            if(pTargetInlineHookInfo->pStubShellCodeAddr != NULL)
            {
                delete pTargetInlineHookInfo->pStubShellCodeAddr;
            }
            if(pTargetInlineHookInfo->ppOldFuncAddr)
            {
                delete *(pTargetInlineHookInfo->ppOldFuncAddr);
            }
            delete pTargetInlineHookInfo;
            bRet = true;
        }
    }

    return bRet;
}

/**
 * hook mono_class_from_name，dump dll
 * @param regs 寄存器结构，保存寄存器当前hook点的寄存器信息
 */
 #define ASSEMBLY_CSHARP_DLL            "Assembly-CSharp.dll"
 #define ASSEMBLY_CSHARP_FIRSTPASS_DLL  "Assembly-CSharp-firstpass.dll"
void HookMonoClassFromName(pt_regs *regs)
{
    // 拿到MonoImage结构体。regs->uregs[0]   --->   pMonoImage
    int nMonoImage = regs->uregs[0];
    // 拿到MonoImage结构体对应的Dll路径。pMonoImage + 0x14   --->   MonoImage.name
    char* pszMonoImagePath = (char*)(*((int*)(nMonoImage + 0x14)));
    
    // 默认只 dump Assembly-CSharp.dll 和 Assembly-CSharp-firstpass.dll
    // 如果设置了系统属性 dumptool.all，则dump所有的Dll
    char pszDumpAll[PROP_VALUE_MAX] = {0};
    __system_property_get("dumptool.all", pszDumpAll); 
    int nDumpAll = 0;
    sscanf(pszDumpAll, "%d", &nDumpAll);    
    
    if (nDumpAll || strstr(pszMonoImagePath, ASSEMBLY_CSHARP_DLL) || strstr(pszMonoImagePath, ASSEMBLY_CSHARP_FIRSTPASS_DLL)) 
    {
        // 拿到Dll的长度
        // pMonoImage + 0xC   --->   MonoImage.raw_data_len
        int nLen = *((int*)(nMonoImage + 0xC));
        // 拿到Dll的内存地址
        // pMonoImage + 0x8   --->   MonoImage.raw_data
        int nBase = *((int*)(nMonoImage + 8));
		LOGI("[find] base = %x , len = %x , name = %s ", nBase, nLen, pszMonoImagePath);
        
        // 拼接dump文件名
        std::string szMonoImagePath = pszMonoImagePath;
        size_t index = szMonoImagePath.find_last_of('/');
        std::string szMonoImageName = szMonoImagePath.substr(index + 1);
        char pszDumpPath[1024] = {0};
        int nSelfPid = getpid();
        sprintf(pszDumpPath, "/data/local/tmp/dumptool.%d.%s", nSelfPid, szMonoImageName.c_str());
        
        // 如果文件不存在，开始dump
        if(access(pszDumpPath, F_OK) == -1)
        {
            LOGI("[dumping...] pid = %d, dump to = %s \n", nSelfPid, pszDumpPath);
            FILE* fd= fopen(pszDumpPath, "wb+");
            if (fd != 0) 
            {
                const int cnBufSize = 0x1000;
                int nCurSize = 0;
                do
                { 
                    LOGI("[dumping...] remain = %d bytes", nLen);
                    nCurSize = nLen > cnBufSize ? cnBufSize : nLen;
                    fwrite((void *)nBase, 1, nCurSize, fd);
                    nBase += nCurSize;
                    nLen -= nCurSize;
                }while(nLen > 0);
                
                fclose(fd);
            }
            else 
            {
                LOGI("[error] create %s fail, maybe /data/local/tmp/ permission denied\n", pszDumpPath);
            }        
        }   
	} 
}

void OnProcessTouchEvents(pt_regs *regs)
{
    LOGI("in OnProcessTouchEvents stub");

    int R0 = int(regs->uregs[0]);
    int R5 = int(regs->uregs[5]);

    regs->uregs[5] = 0;

    LOGI("OnProcessTouchEvents count = %X, index = %X", R0, R5);
}
/**
 * hook mono_compile_method
 * @param regs 寄存器结构，保存寄存器当前hook点的寄存器信息
 */
void HookMonoCompileMethod(pt_regs *regs)
{
    //LOGI("In Hook Stub...");
    //[R11 -8]   --->   pMonoMethod
    //[pMonoMethod + 8]   --->   pMonoClass
    int nMonoClass = (*((int*)((*((int*)(regs->uregs[11] - 8))) + 8)));
    //[pMonoClass + 0x28] --->   pszMonoClassName
    char* pszMonoClassName = (char*)(*((int*)(nMonoClass + 0x28)));
    //[pMonoClass + 0x2C] --->   pszMonoClassSpaceName
    char* pszMonoClassSpaceName = (char*)(*((int*)(nMonoClass + 0x2C)));
    //[pMonoMethod + 16]   --->   pszFunName
    char* pszFunName = (char*)(*((int*)((*((int*)(regs->uregs[11] - 8))) + 16)));
    uint32_t uiFunBase = regs->uregs[3];
    
    if (!strcmp(pszMonoClassName, "TouchInputModule") && !strcmp(pszFunName, "ProcessTouchEvents"))
    {
        LOGI("fun = %s   base = %x", pszFunName, uiFunBase);
        uint32_t uiHookAddr = uiFunBase + 0x3C;
        LOGI("hook TouchInputModule ProcessTouchEvents at %x", uiHookAddr);

        InlineHook((void*)(uiHookAddr), OnProcessTouchEvents);
    }
}

 /**
 * so 入口
 */
void LibMain()
{    
    LOGI("In lib main...");
    
    // hook libmono.so 中 mono_compile_method 倒数第三条指令的位置
    // 这里可以拿到 u3d 脚本编译后的本地代码
    void* pModuleBaseAddr = GetModuleBaseAddr(-1, "libmono.so");
    g_monoBase = (int)pModuleBaseAddr;
    if(pModuleBaseAddr == 0)
    {
        LOGI("get module base error.");
        return;
    }

    // find MonoCompileMethod address in libmono.so
    uint32_t uiHookAddr = (uint32_t)pModuleBaseAddr + 0x001F5510;
    LOGI("mono base = %X, HookAddr is %X", pModuleBaseAddr, uiHookAddr);
    InlineHook((void*)(uiHookAddr), HookMonoCompileMethod);
}
