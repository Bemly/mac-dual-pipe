# mac-dual-pipe

[English](README.md)

macOS 双链二进制直传静态库（纯 Objective-C，零第三方依赖）。

两条链（有线转发 + 无线直连）并发，按实时测速动态分包；单链故障自动转交，
全挂回退备用通道；掉队链路熔断 30s。大流量走纯二进制帧，无文本编码开销。

## 线协议（全大端，两端逐字节对齐）

- 请求 `MAGIC'AD01' + cmd`
  - `M` 批量：slot u32 + iv16B + 条数 u32 + lens[n] u32 + 总长 u32 + 输入
  - `E` 回显：len u32 + bytes
  - `Q` 断开；`V` 代号问询
- 应答 `MAGIC'AD02' + status u8（0=ok）`
  - `M`：条数 u32 + `[len u32 + bytes]*`（无总长前缀，流式直写，按条数读完即止）
  - `E`：len + bytes；`V`：代号原文

## 控制契约（调用方经 `MDPConfig.control` 实现，传输方式不限）

- `start {basePort}` → `{ok, ports:[p1,p2], notes:[]}`（端口占用可顺延）
- `slot spec` → `{ok, slot:n}`（spec 内容调用方自定；线上只走小整数 handle）
- `stop {}` → `{ok, closed:n}`

另需调用方实现 `ensureForward(port)`（保证 `127.0.0.1:port` 可达对端）
并提供无线地址（`lanIp`，无则只用有线）。

## 生命周期纪律

对端服务线程必须**确定性关闭**：`close`（关各链 + control stop）必须在控制通道
失效前调用；异常退出导致残留时，靠端口顺延 + 代号校验（`expectedGen` 对不上即
视为旧实例，跳过）兜底。

## 构建与自测

```bash
# 静态库（双架构）
xcodebuild -project mac-dual-pipe.xcodeproj -target mac-dual-pipe -configuration Release SYMROOT=build build
# → build/Release/libmac-dual-pipe.a，头文件在 src/

# 回环自测（无需设备：进程内桩服务实现分帧，M 的变换=逐字节反转）
clang -arch arm64 -fobjc-arc -framework Foundation tools/mdpsmoke.m \
  build/Release/libmac-dual-pipe.a -I src -o /tmp/mdpsmoke && /tmp/mdpsmoke
```

排障：`DUALPIPE_DEBUG=1` 打开库内打点（stderr）。

## 用法

```objc
MDPConfig *cfg = [MDPConfig new];
cfg.basePort = 17001;
cfg.lanIp = lanIpOrNil;
cfg.expectedGen = @"A7";
cfg.control = ^NSDictionary *(NSString *op, NSDictionary *args, NSTimeInterval t, NSString **e) {
    return MyControl(op, args, t, e);   // start/slot/stop
};
cfg.ensureForward = ^BOOL (int port, NSString **e) {
    return MyEnsureForward(port, e);
};
MDPDual *dual = [MDPDual buildWithConfig:cfg error:&err];
uint32_t slot = [dual slotForKey:cacheKey spec:spec error:&err];
NSArray *out = [dual processMany:slot iv:iv items:in
                        fallback:^NSArray *(NSArray *b, NSString **e) { return MyFallback(b, e); }
                            logf:^(NSString *l) { NSLog(@"%@", l); } error:&err];
[dual close];   // 用完即关，幂等
```

参考性能（本机回环，桩服务做逐字节反转）：建链双链 13MB/s 级；
生产吞吐取决于对端变换速度与真实网络。
