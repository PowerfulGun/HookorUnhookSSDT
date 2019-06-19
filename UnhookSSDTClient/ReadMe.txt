========================================================================
    HookSSDT 项目概述
========================================================================

HookSSDT:	针对Win7 x64 的SSDT的hook,hook了函数NtTerminateProcess,在过滤函
数中会检查是否是计算器(calc.exe)进程,从而保护其进程不被任务管理器进程结束.

UnhookSSDT:	针对Win7 x64 的SSDT的unhook,驱动中会将ssdt中函数的地址返回给UnhookSSDT
Client应用程序或者接收应用程序发送来的地址替换掉ssdt中某个函数地址.

UnhookSSDTClient:	控制台程序,其会分析磁盘上的内核文件并找到ssdt中函数的原始地址
并向驱动UnhookSSDT发送请求获取该函数在ssdt中的当前地址,比较这两个地址是否一致,不一致
的话就是存在hook,应用程序可以选择将函数的原始地址发送给驱动UnhookSSDT,再由驱动将该
函数在ssdt中的当前地址替换成原始地址,从而达到去掉ssdt hook 的目的.