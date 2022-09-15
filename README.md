# DuckMemoryScan
一个简单寻找包括不限于iis劫持,无文件木马,shellcode免杀后门的工具,由huoji花了1天编写,编写时间2021-02-24
!!!本程序需要64位编译才能回溯x64的程序堆栈,请勿执行32位编译!!!
!!!本工具不能代替杀毒软件!!!

# 本项目不再维护
请转到更先进的项目里:  
https://github.com/RoomaSec/RmEye  
https://github.com/RoomaSec/RmTools

# 运行截图
![image](https://raw.githubusercontent.com/huoji120/DuckMemoryScan/master/%E6%BC%94%E7%A4%BA%E5%9B%BE%E7%89%87.png)
![image](https://raw.githubusercontent.com/huoji120/DuckMemoryScan/master/CS%e6%b5%8b%e8%af%95%e5%9b%be%e7%89%87.png)

# 功能列表
1. HWBP hook检测 检测线程中所有疑似被hwbp隐形挂钩
2. 内存免杀shellcode检测(metasploit,Cobaltstrike完全检测)
3. 可疑进程检测(主要针对有逃避性质的进程[如过期签名与多各可执行区段])
4. 无文件落地木马检测(检测所有已知内存加载木马)
5. 简易rootkit检测(检测证书过期/拦截读取/证书无效的驱动)
6. 检测异常模块,检测绝大部分如"iis劫持"的后门(2021年2月26日新增)

# 免杀木马检测原理:
所有所谓的内存免杀后门大部分基于"VirtualAlloc"函数申请内存 之后通过各种莫名其妙的xor甚至是aes加密去混淆shellcode达到"免杀"效果.
本工具通过线程堆栈回溯方法(StackWalkEx函数)遍历线程,寻找系统中在VirtualAlloc区域执行代码的区域,从而揪出"免杀木马"
当然也会存在误报,多常见于加壳程序也会申请VirtualAlloc分配内存.
但大部分普通程序均不会在VirtualAlloc区域内执行代码.一般都是在.text区段内执行代码

# 无文件落地木马检测原理:
所有无文件落地木马都是一个标准PE文件被映射到内存中,主要特征如下:
1. 内存区段有M.Z标志
2. 线程指向一个NOIMAGE内存
本工具将会通过第一种特征检测出所有"无文件落地木马"

# 异常模块检测原理
本工具将会扫描所有带签名程序的模块列表并且检测其中模块是否存在签名,如果不存在则发出提示.本检测存在较多误报,但将会检测到类似IIS劫持的特殊模块

# 使用方式
编译 运行 得到信息列表

# 检测出疑似后门后怎么做?
使用其他工具比如Scylla dump内存做进一步分析,本工具不打算做内存dump系列操作(时间有限不想重复造轮子)

# 如何让堆栈回溯更精准
目前工具只回溯rip与eip,你可以回溯RSP或者EBP 只需修改StackFarmeEx.AddrPC.Offset即可

# 追踪这个项目
白帽wiki是一个公益性质的知识库为所有人在知识付费时代提供一个简单的免费的存储知识的网站.对标vxjump.net,我会无偿的将我的所学到的知识分享在此wiki中,目前涉及到机器学习领域,虚拟化安全领域,传统安全领域,游戏安全领域,EFI硬件安全领域.希望后人能少一点坑.
你可以在此网站中发现一个沉沦很久的讨论群,选择加入,然后一起扯淡聊天.
https://key08.com
