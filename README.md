# iOS-Monitor-Resources

## 背景

在移动设备上开发应用，性能一直是我们最为关心的话题之一，除了需要提高代码质量外，我们还需要能够及时发现我们的应用在使用过程中遇到的各种性能问题。稍微有些经验的 iOS 开发者都知道在 Xcode 中已经集成了非常方便的调试工具 Instruments，它能帮助我们在开发和测试阶段对应用进行分析，但正因如此，也带来了局限性，我们必须依赖 Xcode 环境，并且联机的情况下进行分析工作，那么如何才能让我们能在脱离 Xcode 环境，也能达到对应用的性能进行监控和分析呢？我会将自己分析和搜集各厂商与该领域相关的记录下来，并不断更新文章，这就是我为什么要建这个仓库的原因，同时希望感兴趣的开发者可以一起参与进来。

## 各厂商 SDK 方案分析

### 码力 SDK

[码力 SDK](https://doc.open.alipay.com/docs/doc.htm?spm=a219a.7629140.0.0.Q1Pviy&treeId=186&articleId=105263&docType=1) 是阿里百川的 APM 产品，它主要是通过将探针（软件程序）嵌入到移动应用工程中，支持 iOS 和 Android 两个平台，用于跟踪和反馈用户使用过程中出现的应用崩溃、加载错误以及加载缓慢等各种对用户体验造成负面影响的故障或性能问题。

#### 功能

- [x] 应用崩溃检测和主线程卡顿检测.
- [x] 网络检测，支持 NSURLConnection、NSURLSession、CFNetwork 网络请求的检测.
- [x] 应用中的 webview 页面进行性能数据的分析和性能情况检测，支持 UIWebView 以及 WKWebView 组件.

#### 分析

因为码力 SDK 是闭源的，所以我们没有办法查看他的源码。但我们可以通过反编译工具对其 Framework 文件进行静态分析，从而获得 SDK 的实现细节，笔者以 [Hopper Disassembler](https://www.hopperapp.com/) 为例进行分析，当然也可以使用 hex-rays 公司的反编译工具 [IDA Pro](https://www.hex-rays.com/products/ida/)，

> 反编译工具以及逆向工程相关的基础知识可以参考笔者的仓库[iOS-Reverse-Engineering-presentation](https://github.com/aozhimin/iOS-Reverse-Engineering-presentation)，对逆向工程的工具和基础进行了简单的介绍，可以自己 Google 相关的教程。

``` 
void -[APMNetworkSurveyor startInjection](void * self, void * _cmd) {
    var_38 = self;
    r12 = [+[APMCrashCounter counter](@class(APMConfig), @selector(configuration)) retain];
    rbx = [+[APMCrashCounter counter](r12, @selector(payload)) retain];
    r15 = [+[APMCrashCounter counter](rbx, @selector(objectForKeyedSubscript:)) retain];
    var_30 = r15;
    +[APMCrashCounter counter](rbx, @selector(objectForKeyedSubscript:));
    +[APMCrashCounter counter](r12, @selector(objectForKeyedSubscript:));
    rbx = [+[APMCrashCounter counter](r15, @selector(objectForKeyedSubscript:)) retain];
    +[APMCrashCounter counter](rbx, @selector(boolValue)) & 0xff;
    +[APMCrashCounter counter](var_38, @selector(setDebug:));
    +[APMCrashCounter counter](rbx, @selector(setDebug:));
    rdi = r15;
    rbx = [+[APMCrashCounter counter](rdi, @selector(objectForKeyedSubscript:)) retain];
    r12 = +[APMCrashCounter counter](rbx, @selector(boolValue));
    +[APMCrashCounter counter](rbx, @selector(boolValue));
    if (r12 != 0x0) {
            r14 = var_38;
            rbx = [+[APMCrashCounter counter](@class(APMNSURLConnectionInjector), @selector(injectorWithDelegate:), r14) retain];
            rdx = rbx;
            +[APMCrashCounter counter](r14, @selector(setConnectionInjector:), rdx);
            +[APMCrashCounter counter](rbx, @selector(setConnectionInjector:), rdx);
            rbx = [+[APMCrashCounter counter](r14, @selector(connectionInjector), rdx) retain];
            +[APMCrashCounter counter](rbx, @selector(inject), rdx);
            +[APMCrashCounter counter](rbx, @selector(inject), rdx);
            rax = +[APMCrashCounter counter](r14, @selector(debug), rdx);
            var_3C = 0x1;
            if (rax != 0x0) {
                    _NSLog(@"[APMPlus] NSURLConnection network survey started.");
            }
    }
    else {
            r14 = var_38;
            var_3C = 0x0;
    }
    rcx = 0x1;
    rbx = [+[APMCrashCounter counter](var_30, @selector(objectForKeyedSubscript:), @"NeedsNSURLSession", rcx) retain];
    r12 = +[APMCrashCounter counter](rbx, @selector(boolValue), @"NeedsNSURLSession", rcx);
    +[APMCrashCounter counter](rbx, @selector(boolValue));
    COND = r12 == 0x0;
    r12 = r14;
    r14 = +[APMCrashCounter counter];
    if (!COND) {
            rbx = [(r14)(@class(APMNSURLSessionInjector), @selector(injectorWithDelegate:), r12, rcx) retain];
            rdx = rbx;
            (r14)(r12, @selector(setSessionInjector:), rdx, rcx);
            +[APMCrashCounter counter](rbx, @selector(setSessionInjector:));
            rbx = [(r14)(r12, @selector(sessionInjector), rdx, rcx) retain];
            (r14)(rbx, @selector(inject), rdx, rcx);
            +[APMCrashCounter counter](rbx, @selector(inject));
            rax = (r14)(r12, @selector(debug), rdx, rcx);
            var_3C = 0x1;
            if (rax != 0x0) {
                    _NSLog(@"[APMPlus] NSURLSession network survey started.");
            }
    }
    rcx = 0x1;
    rdx = @"NeedsCFNetwork";
    rbx = [(r14)(var_30, @selector(objectForKeyedSubscript:), rdx, rcx) retain];
    rsi = @selector(boolValue);
    r15 = (r14)(rbx, rsi, rdx, rcx);
    +[APMCrashCounter counter](rbx, rsi);
    if (r15 != 0x0) {
            rbx = [(r14)(@class(APMCFNetworkInjector), @selector(injector), rdx, rcx) retain];
            (r14)(r12, @selector(setNetworkInjector:), rbx, rcx);
            +[APMCrashCounter counter](rbx, @selector(setNetworkInjector:));
            rbx = [(r14)(r12, @selector(networkInjector), rbx, rcx) retain];
            (r14)(rbx, @selector(setDelegate:), r12, rcx);
            +[APMCrashCounter counter](rbx, @selector(setDelegate:));
            rbx = [(r14)(r12, @selector(networkInjector), r12, rcx) retain];
            (r14)(rbx, @selector(inject), r12, rcx);
            +[APMCrashCounter counter](rbx, @selector(inject));
            if ((r14)(r12, @selector(debug), r12, rcx) != 0x0) {
                    _NSLog(@"[APMPlus] CFNetwork network survey started.");
            }
            rsi = @selector(track);
            +[APMCrashCounter counter](r12, rsi);
    }
    else {
            if (var_3C != 0x0) {
                    rsi = @selector(track);
                    +[APMCrashCounter counter](r12, rsi);
            }
    }
    +[APMCrashCounter counter](var_30, rsi);
    return;
}
 
```

> 友情提示：百川已经发出公告码力 APP 监控产品将于今年5月份开始逐步下线，不过 SDK 本身还是具有一定研究价值的。


## 资源

### 视频资源

> **APMCon** 是由 **InfoQ**、极客邦与听云联合主办的高水准 **APM** 技术盛会，聚焦当前最为热门的移动端、**Web** 端和 **Server** 端的性能监控和管理技术，整个会议设置包含了：性能可视化、服务端监控实践、运维自动化、数据库性能优化、**APM** 云服务架构和 **HTML5** 调优最佳实践等话题。
**APMCon** 内容源于实践并面向社区，来自国内外的演讲嘉宾依据热点话题，面向5年以上的技术团队负责人、中高级开发和运维人员、工程总监分享 **APM** 技术创新、趋势和最佳实践。

读者可以直接去[官网](http://www.apmcon.cn/)观看，但是我发现上面的视频观看非常卡，而 **APMCon** 的演讲实录视频资源放在 **AWS** 上，所以下面直接列出与主题相关的视频的链接，读者可以使用**迅雷**等工具下载到本地磁盘后观看。

* [性能可视化实践之路](https://s3.cn-north-1.amazonaws.com.cn/market.tingyun.com/video/apmcon/18-A-04.mp4) By 陈武 阿里巴巴高级无线技术专家
* [网易 APM hook 方案探索](https://s3.cn-north-1.amazonaws.com.cn/market.tingyun.com/video/apmcon/19-C-05.mp4) By 郑文 网易杭州研究院资深工程师
* [网易 APM hook 方案探索](https://s3.cn-north-1.amazonaws.com.cn/market.tingyun.com/video/apmcon/19-C-05.mp4) By 郑文 网易杭州研究院资深工程师
* [浅谈App优化](https://s3.cn-north-1.amazonaws.com.cn/market.tingyun.com/video/apmcon/19-C-06.mp4) By 胡彪 饿了么移动技术部高级研发经理
* [映客直播 iOS App 性能优化实践](https://s3.cn-north-1.amazonaws.com.cn/market.tingyun.com/video/apmcon/19-C-07.mp4) By 刘凯 映客直播iOS高级开发工程师
