#import "MDPDual.h"
#import "MDPLink.h"

static const NSUInteger kMinSplit = 256000;   // 小于此总量只走最快单链
static const NSUInteger kUnitBytes = 1048576; // 切片上限:大于此的条目再拆(解密语义逐条独立+真 IV,结果可拼)
static const NSUInteger kPoisonAfter = 4;     // 单片连续失败超此数即毒片(不再重排,走批量兜底/判失败)
static const NSTimeInterval kHelpFloor = 4.0; // 掉队转交下限(秒):在飞超 max(此值, 3×平均片耗时)即复制给空闲链
static const double kEwmaNew = 0.35;
static const int kDefaultBasePort = 17001;

static BOOL TLDebugOn(void) {
    static BOOL v;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ v = getenv("DUALPIPE_DEBUG") != NULL; });
    return v;
}
#define TLDBG(fmt, ...) do { if (TLDebugOn()) NSLog(@"[TL] " fmt, ##__VA_ARGS__); } while (0)

static void LogTo(void (^logf)(NSString *), NSString *fmt, ...) {
    if (!logf) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    logf(s);
}

@implementation MDPConfig
@end

@interface MDPDual ()
@property (nonatomic, strong) MDPConfig *cfg;
@property (nonatomic, strong) NSMutableArray<MDPLink *> *links;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *slots;
@property (nonatomic, strong) NSLock *mx;
@property (nonatomic, assign) BOOL shut;
@end

@implementation MDPDual

- (instancetype)init {
    if ((self = [super init])) {
        _links = [NSMutableArray array];
        _slots = [NSMutableDictionary dictionary];
        _mx = [NSLock new];
    }
    return self;
}

- (NSUInteger)linkTotal { return self.links.count; }

- (void)emit:(void (^ _Nullable)(NSString *))logf fmt:(NSString *)fmt, ... {
    void (^dst)(NSString *) = logf ?: self.cfg.log;
    if (!dst) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    dst(s);
}

+ (nullable instancetype)buildWithConfig:(MDPConfig *)cfg
                                  error:(NSString **)err {
    if (!cfg.control || !cfg.ensureForward) {
        if (err) *err = @"配置缺 control/ensureForward";
        return nil;
    }
    int base = cfg.basePort > 0 ? cfg.basePort : kDefaultBasePort;
    if (base > 65530) base = kDefaultBasePort;
    NSString *e = nil;
    NSDictionary *resp = cfg.control(@"start", @{ @"basePort": @(base) }, 30, &e);
    NSArray *ports = resp[@"ports"];
    if (!resp || ![resp[@"ok"] boolValue] || ports.count != 2) {
        if (err) *err = e ?: [NSString stringWithFormat:@"起服务被拒: %@", resp[@"error"] ?: @"?"];
        return nil;
    }
    int p1 = [ports[0] intValue], p2 = [ports[1] intValue];

    MDPDual *dual = [[MDPDual alloc] init];
    dual.cfg = cfg;
    if ([resp[@"notes"] count])
        [dual emit:nil fmt:@"[*] 端口占用记录: %@", [resp[@"notes"] componentsJoinedByString:@"; "]];
    [dual emit:nil fmt:@"[*] 端口对: %d/%d", p1, p2];
    TLDBG(@"端口对 %d/%d notes=%@", p1, p2, resp[@"notes"]);

    if (!cfg.ensureForward(p1, &e)) {
        if (err) *err = e ?: @"本地转发失败";
        return nil;
    }

    NSData *ping = [@"twinlink-ping" dataUsingEncoding:NSUTF8StringEncoding];

    // 有线链路:握手(echo+代号,识破旧实例)
    MDPLink *wired = [[MDPLink alloc] initWithName:@"wired" addr:@"127.0.0.1" port:p1 error:&e];
    if (wired) {
        NSString *gen = [wired echo:ping error:&e] ? [wired queryGenWithError:&e] : nil;
        BOOL genOk = !cfg.expectedGen.length || [gen isEqualToString:cfg.expectedGen];
        if (!genOk) {
            [dual emit:nil fmt:@"[!] 有线链路跳过: %@", e ?: [NSString stringWithFormat:@"代号 %@ 对不上", gen ?: @"?"]];
            [wired close];
            wired = nil;
        }
    } else {
        [dual emit:nil fmt:@"[!] 有线链路跳过: %@", e ?: @"?"];
    }
    if (wired) {
        [dual.links addObject:wired];
        [dual emit:nil fmt:@"[*] 链路 wired 127.0.0.1:%d 通", p1];
    }

    // 无线链路:地址由调用方给(取不到则只用有线)
    if (cfg.lanIp.length) {
        MDPLink *wifi = [[MDPLink alloc] initWithName:@"wifi" addr:cfg.lanIp port:p2 error:&e];
        if (wifi) {
            NSString *gen = [wifi echo:ping error:&e] ? [wifi queryGenWithError:&e] : nil;
            BOOL genOk = !cfg.expectedGen.length || [gen isEqualToString:cfg.expectedGen];
            if (!genOk) {
                [dual emit:nil fmt:@"[!] 无线链路跳过(%@): %@", cfg.lanIp, e ?: @"代号对不上"];
                [wifi close];
                wifi = nil;
            }
        } else {
            [dual emit:nil fmt:@"[!] 无线链路跳过(%@): %@", cfg.lanIp, e ?: @"?"];
        }
        if (wifi) {
            [dual.links addObject:wifi];
            [dual emit:nil fmt:@"[*] 链路 wifi %@:%d 通", cfg.lanIp, p2];
        }
    } else {
        [dual emit:nil fmt:@"[*] 无无线地址,只用有线"];
    }

    if (!dual.links.count) {
        [dual close];
        if (err) *err = @"双链全挂";
        return nil;
    }

    // 64KB 回显定初始权重(只分方向,真实权重靠传输 EWMA 纠正)
    NSMutableData *blob = [NSMutableData dataWithLength:65536];
    arc4random_buf(blob.mutableBytes, blob.length);
    NSMutableArray<MDPLink *> *ups = [NSMutableArray array];
    for (MDPLink *l in dual.links) {
        NSTimeInterval t0 = [NSDate date].timeIntervalSince1970;
        if ([l echo:blob error:&e]) {
            l.weight = blob.length * 2 / MAX([NSDate date].timeIntervalSince1970 - t0, 0.01);
            [ups addObject:l];
        } else {
            l.down = YES;
            [dual emit:nil fmt:@"[!] %@ 测速失败,标 down: %@", l.name, e ?: @"?"];
        }
    }
    dual.links = ups;
    if (!dual.links.count) {
        [dual close];
        if (err) *err = @"双链全挂";
        return nil;
    }
    NSMutableArray<NSString *> *ws = [NSMutableArray array];
    for (MDPLink *l in dual.links)
        [ws addObject:[NSString stringWithFormat:@"%@=%.2fMB/s", l.name, l.weight / 1e6]];
    [dual emit:nil fmt:@"[*] 链路权重: %@", [ws componentsJoinedByString:@" "]];
    TLDBG(@"建链完成 %lu 条", (unsigned long)dual.links.count);
    return dual;
}

- (uint32_t)slotForKey:(NSString *)cacheKey
                  spec:(NSDictionary *)spec
                 error:(NSString **)err {
    [self.mx lock];
    NSNumber *hit = self.slots[cacheKey];
    [self.mx unlock];
    if (hit) return hit.unsignedIntValue;
    NSString *e = nil;
    NSDictionary *resp = self.cfg.control(@"slot", spec, 30, &e);
    uint32_t slot = (uint32_t)[resp[@"slot"] unsignedIntValue];
    if (!resp || ![resp[@"ok"] boolValue] || !slot) {
        if (err) *err = e ?: @"槽位登记失败";
        return 0;
    }
    [self.mx lock];
    self.slots[cacheKey] = @(slot);
    [self.mx unlock];
    TLDBG(@"槽位登记 slot=%u", slot);
    return slot;
}

- (void)note:(MDPLink *)l sent:(NSUInteger)s recv:(NSUInteger)r dt:(NSTimeInterval)dt {
    l.weight = kEwmaNew * (s + r) / MAX(dt, 0.01) + (1 - kEwmaNew) * l.weight;
}

- (nullable NSArray<NSData *> *)processMany:(uint32_t)slot
                                         iv:(NSData *)iv
                                      items:(NSArray<NSData *> *)cts
                                   fallback:(nullable NSArray<NSData *> *(^)(NSArray<NSData *> *batch, NSString * _Nullable * _Nullable ferr))fallback
                                       logf:(void (^ _Nullable)(NSString *))logf
                                      error:(NSString **)err {
    // 空输入占位(保序,调用方按原下标回填)
    NSMutableArray<NSData *> *out = [NSMutableArray arrayWithCapacity:cts.count];
    NSMutableArray<NSNumber *> *idx = [NSMutableArray array];
    NSMutableArray<NSData *> *valid = [NSMutableArray array];
    for (NSUInteger i = 0; i < cts.count; i++) {
        [out addObject:[NSData data]];
        if (cts[i].length) { [idx addObject:@(i)]; [valid addObject:cts[i]]; }
    }
    if (!valid.count) return out;

    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    for (MDPLink *l in self.links)
        if (l.down && l.resumeAt <= now) {
            l.down = NO;
            [self emit:logf fmt:@"[*] %@ 熔断结束,恢复试用", l.name];
        }
    NSMutableArray<MDPLink *> *ups = [NSMutableArray array];
    for (MDPLink *l in self.links) if (!l.down) [ups addObject:l];
    NSUInteger total = 0;
    for (NSData *d in valid) total += d.length;

    // 全挂 → 整体走备用通道
    if (!ups.count) {
        if (!fallback) { if (err) *err = @"双链全挂且无兜底"; return nil; }
        NSString *e = nil;
        NSArray<NSData *> *fb = fallback(valid, &e);
        if (!fb) { if (err) *err = e ?: @"兜底失败"; return nil; }
        for (NSUInteger i = 0; i < idx.count; i++) out[idx[i].unsignedIntegerValue] = fb[i];
        return out;
    }

    // 单链或小总量:整包走最快链(旧语义,不切片)
    if (ups.count == 1 || total < kMinSplit) {
        MDPLink *best = ups[0];
        for (MDPLink *l in ups) if (l.weight > best.weight) best = l;
        NSString *e = nil;
        NSTimeInterval t0 = [NSDate date].timeIntervalSince1970;
        NSArray<NSData *> *res = [best process:slot iv:iv items:valid error:&e];
        if (res) {
            NSUInteger sb = 0, rb = 0;
            for (NSData *d in valid) sb += d.length;
            for (NSData *d in res) rb += d.length;
            [self note:best sent:sb recv:rb dt:[NSDate date].timeIntervalSince1970 - t0];
            for (NSUInteger i = 0; i < idx.count; i++) out[idx[i].unsignedIntegerValue] = res[i];
            return out;
        }
        best.down = YES;
        [self emit:logf fmt:@"[!] %@ 失败转交: %@", best.name, e ?: @"?"];
        TLDBG(@"%@ 失败转交 %@", best.name, e ?: @"?");
        MDPLink *alt = nil;
        for (MDPLink *x in self.links) {
            if (x == best || x.down) continue;
            if (!alt || x.weight > alt.weight) alt = x;
        }
        if (alt) {
            NSString *e2 = nil;
            NSTimeInterval t1 = [NSDate date].timeIntervalSince1970;
            NSArray<NSData *> *res2 = [alt process:slot iv:iv items:valid error:&e2];
            if (res2) {
                NSUInteger sb = 0, rb = 0;
                for (NSData *d in valid) sb += d.length;
                for (NSData *d in res2) rb += d.length;
                [self note:alt sent:sb recv:rb dt:[NSDate date].timeIntervalSince1970 - t1];
                for (NSUInteger i = 0; i < idx.count; i++) out[idx[i].unsignedIntegerValue] = res2[i];
                return out;
            }
            alt.down = YES;
            [self emit:logf fmt:@"[!] %@ 接管也失败,回退备用通道", alt.name];
        }
        if (!fallback) { if (err) *err = @"链路失败且无兜底"; return nil; }
        NSString *e3 = nil;
        NSArray<NSData *> *fb = fallback(valid, &e3);
        if (!fb) { if (err) *err = e3 ?: @"兜底失败"; return nil; }
        for (NSUInteger i = 0; i < idx.count; i++) out[idx[i].unsignedIntegerValue] = fb[i];
        return out;
    }

    // 多链:大切片 + 拉取队列 + 掉队转交。
    // 旧逻辑按权重预切连续段,慢链拖尾(实测 wifi 0.5MB/s 时有线闲置)。
    // 新逻辑:条目再拆成 ≤1MB 单元,各链拉取(快的自然多拿);队列空后空闲链把超时的
    // 在飞单元复制一份并跑(先到先得,解密结果幂等),慢链不再决定总时长。保序由 idx 回填保证。
    NSMutableArray<NSDictionary *> *slices = [NSMutableArray array];
    NSUInteger seq = 0;
    for (NSUInteger vi = 0; vi < valid.count; vi++) {
        NSData *d = valid[vi];
        NSUInteger off = 0;
        do {
            NSUInteger n = MIN(kUnitBytes, d.length - off);
            [slices addObject:@{ @"seq": @(seq++), @"vi": @(vi),
                                 @"data": [d subdataWithRange:NSMakeRange(off, n)],
                                 @"attempts": @0 }];
            off += n;
        } while (off < d.length);
    }
    TLDBG(@"切片 %lu 个(总量 %luB)", (unsigned long)slices.count, (unsigned long)total);

    NSMutableArray<NSDictionary *> *q = [slices mutableCopy];
    NSMutableDictionary<NSNumber *, NSMutableDictionary *> *flight = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSNumber *, NSData *> *got = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSNumber *> *shares = [NSMutableDictionary dictionary]; // 各链拿走片数
    NSLock *qlock = [NSLock new];
    __block double avgUnit = 0.5;
    dispatch_group_t grp = dispatch_group_create();
    for (MDPLink *wl in ups) {
        MDPLink *me = wl;
        dispatch_group_enter(grp);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (;;) {
                NSDictionary *u = nil;
                [qlock lock];
                if (q.count) {
                    u = q[0];
                    [q removeObjectAtIndex:0];
                } else {
                    // 掉队转交:队列已空,复制超时的在飞单元给本空闲链
                    NSTimeInterval tnow = [NSDate date].timeIntervalSince1970;
                    double lim = MAX(kHelpFloor, 3.0 * avgUnit);
                    for (NSNumber *k in flight) {
                        NSMutableDictionary *rec = flight[k];
                        if ([rec[@"done"] boolValue] || [rec[@"helped"] boolValue]) continue;
                        if (tnow - [rec[@"start"] doubleValue] > lim) {
                            rec[@"helped"] = @YES;
                            u = rec[@"unit"];
                            [self emit:logf fmt:@"[*] %@ 掉队转交: 片%@ 超时,接管", me.name, k];
                            TLDBG(@"%@ 掉队转交片 %@", me.name, k);
                            break;
                        }
                    }
                }
                if (!u) {
                    if (q.count == 0 && flight.count == 0) { [qlock unlock]; break; }
                    [qlock unlock];
                    [NSThread sleepForTimeInterval:0.05];
                    continue;
                }
                NSNumber *sq = u[@"seq"];
                NSMutableDictionary *rec = flight[sq];
                if (!rec) {
                    if (got[sq]) { [qlock unlock]; continue; }   // 对方已胜出:丢弃
                    rec = [@{ @"unit": u, @"execs": @0, @"helped": @NO,
                              @"done": @NO, @"start": @([NSDate date].timeIntervalSince1970) } mutableCopy];
                    flight[sq] = rec;
                }
                rec[@"execs"] = @([rec[@"execs"] unsignedIntegerValue] + 1);
                [qlock unlock];

                NSTimeInterval st = [NSDate date].timeIntervalSince1970;
                NSString *e = nil;
                NSArray<NSData *> *res = [me process:slot iv:iv items:@[u[@"data"]] error:&e];
                NSTimeInterval dt = [NSDate date].timeIntervalSince1970 - st;
                NSUInteger sblen = [u[@"data"] length];

                [qlock lock];
                NSMutableDictionary *r2 = flight[sq];
                if (res && r2 && ![r2[@"done"] boolValue]) {
                    avgUnit = 0.3 * dt + 0.7 * avgUnit;   // 只拿成功样本喂(失败的超时会顶飞阈值)
                    r2[@"done"] = @YES;
                    got[sq] = res[0];
                    [flight removeObjectForKey:sq];
                    shares[me.name] = @([shares[me.name] unsignedIntegerValue] + 1);
                    [qlock unlock];
                    [self note:me sent:sblen recv:[res[0] length] dt:dt];
                    continue;
                }
                if (res || got[sq]) { [qlock unlock]; continue; }   // 对方已胜出:丢弃
                // 失败:本链标 down,退出(活链接管;全挂则收尾扫遗漏)
                me.down = YES;
                [self emit:logf fmt:@"[!] %@ 失败退出: %@", me.name, e ?: @"?"];
                TLDBG(@"%@ 失败退出 %@", me.name, e ?: @"?");
                NSUInteger execs = r2 ? [r2[@"execs"] unsignedIntegerValue] : 1;
                if (r2) r2[@"execs"] = @(execs > 0 ? execs - 1 : 0);
                if (r2 && [r2[@"execs"] unsignedIntegerValue] == 0) {
                    NSUInteger at = [u[@"attempts"] unsignedIntegerValue] + 1;
                    [flight removeObjectForKey:sq];
                    if (at <= kPoisonAfter) {
                        NSMutableDictionary *nu = [u mutableCopy];
                        nu[@"attempts"] = @(at);
                        [q insertObject:nu atIndex:0];
                    } else {
                        [self emit:logf fmt:@"[!] 片%@ 多次失败,转备用", sq];
                    }
                    // 注:超次单元不再重排,收尾时统一走一次备用(保持批量语义)
                }
                [qlock unlock];
                break;
            }
            dispatch_group_leave(grp);
        });
    }
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    // 收尾:遗漏(毒片/全挂残留)一次性走备用通道
    NSMutableArray<NSData *> *missData = [NSMutableArray array];
    NSMutableArray<NSNumber *> *missSeq = [NSMutableArray array];
    for (NSDictionary *s in slices) {
        if (!got[s[@"seq"]]) { [missData addObject:s[@"data"]]; [missSeq addObject:s[@"seq"]]; }
    }
    if (missSeq.count) {
        if (!fallback) { if (err) *err = @"链路失败且无兜底"; return nil; }
        NSString *e4 = nil;
        NSArray<NSData *> *fb = fallback(missData, &e4);
        if (!fb || fb.count != missData.count) { if (err) *err = e4 ?: @"兜底失败"; return nil; }
        for (NSUInteger i = 0; i < missSeq.count; i++) got[missSeq[i]] = fb[i];
    }
    // 按 vi 拼回(切片按 seq 递增生成,同 vi 内即有序)
    NSMutableDictionary<NSNumber *, NSMutableData *> *perVi = [NSMutableDictionary dictionary];
    for (NSDictionary *s in slices) {
        NSMutableData *c = perVi[s[@"vi"]];
        if (!c) { c = [NSMutableData data]; perVi[s[@"vi"]] = c; }
        [c appendData:got[s[@"seq"]]];
    }
    for (NSUInteger i = 0; i < idx.count; i++) out[idx[i].unsignedIntegerValue] = perVi[@(i)];
    {
        NSMutableArray<NSString *> *ws = [NSMutableArray array];
        for (MDPLink *l in ups) [ws addObject:[NSString stringWithFormat:@"%@=%@", l.name, shares[l.name] ?: @0]];
        TLDBG(@"分片消化 %@", [ws componentsJoinedByString:@" "]);
        [self emit:logf fmt:@"[*] 分片消化(%lu 片): %@", (unsigned long)slices.count, [ws componentsJoinedByString:@" "]];
    }
    // 掉队熔断:不足最快链一成且还有别链可用,停 30s
    NSMutableArray<MDPLink *> *act = [NSMutableArray array];
    for (MDPLink *l in self.links) if (!l.down) [act addObject:l];
    if (act.count > 1) {
        double best = 0;
        for (MDPLink *l in act) if (l.weight > best) best = l.weight;
        for (MDPLink *l in act) {
            if (l.weight < 0.1 * best) {
                l.down = YES;
                l.resumeAt = [NSDate date].timeIntervalSince1970 + 30;
                [self emit:logf fmt:@"[*] %@ 太慢(%.2f vs %.2fMB/s),熔断30s",
                     l.name, l.weight / 1e6, best / 1e6];
            }
        }
    }
    return out;
}

- (BOOL)echoAll:(NSData *)data logf:(void (^ _Nullable)(NSString *))logf {
    BOOL all = YES;
    for (MDPLink *l in self.links) {
        NSString *e = nil;
        BOOL ok = [l echo:data error:&e];
        [self emit:logf fmt:@"[*] %@ 回环 %luKB %@", l.name, (unsigned long)data.length / 1024,
             ok ? @"OK" : [NSString stringWithFormat:@"失败(%@)", e ?: @"?"]];
        TLDBG(@"回环 %@ %@", l.name, ok ? @"OK" : (e ?: @"?"));
        if (!ok) all = NO;
    }
    return all;
}

- (BOOL)fetchFile:(NSString *)phonePath
           toPath:(NSString *)localPath
        totalSize:(uint64_t)totalSize
             logf:(void (^ _Nullable)(NSString *))logf
            error:(NSString **)err {
    if (!totalSize) { if (err) *err = @"成品大小未知"; return NO; }
    if (![[NSFileManager defaultManager] createFileAtPath:localPath contents:nil attributes:nil]) {
        if (err) *err = @"本地成品创建失败";
        return NO;
    }
    // 单链:直取(旧语义)
    if (self.links.count == 1) {
        MDPLink *l = self.links[0];
        NSString *e = nil;
        NSTimeInterval t0 = [NSDate date].timeIntervalSince1970;
        BOOL ok = [l fetchFile:phonePath offset:0 length:totalSize toPath:localPath error:&e];
        [self note:l sent:totalSize recv:(ok ? totalSize : 0) dt:[NSDate date].timeIntervalSince1970 - t0];
        if (ok)
            [self emit:logf fmt:@"[*] 双链回传完成 %llu 字节(1 段)", totalSize];
        else if (err) *err = e;
        return ok;
    }
    // 多链:≤1MB 切片 + 拉取队列 + 掉队转交(pwrite 按偏移,重复写同段无害,转交天然安全)。
    // 旧逻辑按权重预切大段,慢链拖尾;新逻辑快的自然多拿,空闲链接管超时在飞段。
    NSMutableArray<NSDictionary *> *slices = [NSMutableArray array];
    NSUInteger seq = 0;
    for (uint64_t off = 0; off < totalSize;) {
        uint64_t n = MIN((uint64_t)kUnitBytes, totalSize - off);
        [slices addObject:@{ @"seq": @(seq++), @"off": @(off), @"len": @(n), @"attempts": @0 }];
        off += n;
    }
    TLDBG(@"取文件 %llu 字节切 %lu 片", totalSize, (unsigned long)slices.count);

    NSMutableArray<NSDictionary *> *q = [slices mutableCopy];
    NSMutableDictionary<NSNumber *, NSMutableDictionary *> *flight = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSNumber *, NSNumber *> *got = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSNumber *> *shares = [NSMutableDictionary dictionary];
    NSLock *qlock = [NSLock new];
    __block double avgUnit = 0.5;
    __block NSString *lastFail = nil;
    dispatch_group_t grp = dispatch_group_create();
    for (MDPLink *wl in self.links) {
        MDPLink *me = wl;
        dispatch_group_enter(grp);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (;;) {
                NSDictionary *u = nil;
                [qlock lock];
                if (q.count) {
                    u = q[0];
                    [q removeObjectAtIndex:0];
                } else {
                    NSTimeInterval tnow = [NSDate date].timeIntervalSince1970;
                    double lim = MAX(kHelpFloor, 3.0 * avgUnit);
                    for (NSNumber *k in flight) {
                        NSMutableDictionary *rec = flight[k];
                        if ([rec[@"done"] boolValue] || [rec[@"helped"] boolValue]) continue;
                        if (tnow - [rec[@"start"] doubleValue] > lim) {
                            rec[@"helped"] = @YES;
                            u = rec[@"unit"];
                            [self emit:logf fmt:@"[*] %@ 掉队转交: 片%@ 超时,接管", me.name, k];
                            TLDBG(@"%@ 掉队转交片 %@", me.name, k);
                            break;
                        }
                    }
                }
                if (!u) {
                    if (q.count == 0 && flight.count == 0) { [qlock unlock]; break; }
                    [qlock unlock];
                    [NSThread sleepForTimeInterval:0.05];
                    continue;
                }
                NSNumber *sq = u[@"seq"];
                NSMutableDictionary *rec = flight[sq];
                if (!rec) {
                    if (got[sq]) { [qlock unlock]; continue; }
                    rec = [@{ @"unit": u, @"execs": @0, @"helped": @NO,
                              @"done": @NO, @"start": @([NSDate date].timeIntervalSince1970) } mutableCopy];
                    flight[sq] = rec;
                }
                rec[@"execs"] = @([rec[@"execs"] unsignedIntegerValue] + 1);
                [qlock unlock];

                uint64_t off = [u[@"off"] unsignedLongLongValue];
                uint64_t len = [u[@"len"] unsignedLongLongValue];
                NSTimeInterval st = [NSDate date].timeIntervalSince1970;
                NSString *e = nil;
                BOOL ok = [me fetchFile:phonePath offset:off length:len toPath:localPath error:&e];
                NSTimeInterval dt = [NSDate date].timeIntervalSince1970 - st;

                [qlock lock];
                NSMutableDictionary *r2 = flight[sq];
                if (ok && r2 && ![r2[@"done"] boolValue]) {
                    avgUnit = 0.3 * dt + 0.7 * avgUnit;
                    r2[@"done"] = @YES;
                    got[sq] = @YES;
                    [flight removeObjectForKey:sq];
                    shares[me.name] = @([shares[me.name] unsignedIntegerValue] + 1);
                    [qlock unlock];
                    [self note:me sent:(NSUInteger)len recv:(NSUInteger)len dt:dt];
                    continue;
                }
                if (ok || got[sq]) { [qlock unlock]; continue; }
                me.down = YES;
                lastFail = e ?: @"?";
                [self emit:logf fmt:@"[!] %@ 取片失败退出: %@", me.name, e ?: @"?"];
                TLDBG(@"%@ 取片失败退出 %@", me.name, e ?: @"?");
                NSUInteger execs = r2 ? [r2[@"execs"] unsignedIntegerValue] : 1;
                if (r2) r2[@"execs"] = @(execs > 0 ? execs - 1 : 0);
                if (r2 && [r2[@"execs"] unsignedIntegerValue] == 0) {
                    NSUInteger at = [u[@"attempts"] unsignedIntegerValue] + 1;
                    [flight removeObjectForKey:sq];
                    if (at <= kPoisonAfter) {
                        NSMutableDictionary *nu = [u mutableCopy];
                        nu[@"attempts"] = @(at);
                        [q insertObject:nu atIndex:0];
                    } else {
                        [self emit:logf fmt:@"[!] 片%@ 多次失败,放弃", sq];
                    }
                }
                [qlock unlock];
                break;
            }
            dispatch_group_leave(grp);
        });
    }
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
    NSUInteger done = got.count;
    if (done == slices.count) {
        NSMutableArray<NSString *> *ws = [NSMutableArray array];
        for (MDPLink *l in self.links) {
            if ([shares[l.name] unsignedIntegerValue])
                [ws addObject:[NSString stringWithFormat:@"%@=%@", l.name, shares[l.name]]];
        }
        [self emit:logf fmt:@"[*] 双链回传完成 %llu 字节(%lu 片:%@)", totalSize,
             (unsigned long)slices.count, [ws componentsJoinedByString:@" "]];
        return YES;
    }
    if (err) *err = [NSString stringWithFormat:@"取段失败(%lu/%lu): %@",
                     (unsigned long)(slices.count - done), (unsigned long)slices.count, lastFail ?: @"?"];
    return NO;
}

- (void)close {
    [self.mx lock];
    if (self.shut) { [self.mx unlock]; return; }
    self.shut = YES;
    NSArray *links = [self.links copy];
    [self.links removeAllObjects];
    MDPConfig *cfg = self.cfg;
    self.cfg = nil;
    [self.mx unlock];
    for (MDPLink *l in links) [l close];
    // 确定性清理:停对端服务(必须在控制通道失效前调)
    if (cfg.control) {
        NSDictionary *resp = cfg.control(@"stop", @{}, 10, NULL);
        TLDBG(@"stop closed=%@", resp[@"closed"]);
    }
    TLDBG(@"双链已关");
}

- (void)dealloc { [self close]; }

@end
