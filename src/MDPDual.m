#import "MDPDual.h"
#import "MDPLink.h"

static const NSUInteger kMinSplit = 256000;   // 小于此总量只走最快单链
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

    // 分包:单链或小总量只走最快链;否则按权重把序列切连续段(保序、按字节比例)
    NSMutableArray<NSArray *> *shares = [NSMutableArray array]; // @[link, @[valid 下标...]]
    if (ups.count == 1 || total < kMinSplit) {
        MDPLink *best = ups[0];
        for (MDPLink *l in ups) if (l.weight > best.weight) best = l;
        NSMutableArray *g = [NSMutableArray array];
        for (NSUInteger i = 0; i < valid.count; i++) [g addObject:@(i)];
        [shares addObject:@[best, g]];
    } else {
        double wsum = 0;
        for (MDPLink *l in ups) wsum += l.weight;
        NSUInteger start = 0;
        for (NSUInteger li = 0; li < ups.count; li++) {
            MDPLink *l = ups[li];
            if (li == ups.count - 1) {
                NSMutableArray *g = [NSMutableArray array];
                for (NSUInteger i = start; i < valid.count; i++) [g addObject:@(i)];
                if (g.count) [shares addObject:@[l, g]];
            } else {
                double need = total * l.weight / wsum;
                NSUInteger j = start, s = 0;
                while (j < valid.count && s < need) { s += valid[j].length; j++; }
                if (j <= start) j = start + 1;
                NSMutableArray *g = [NSMutableArray array];
                for (NSUInteger i = start; i < j; i++) [g addObject:@(i)];
                if (g.count) [shares addObject:@[l, g]];
                start = j;
            }
        }
    }
    TLDBG(@"分包 %lu 组(总量 %luB)", (unsigned long)shares.count, (unsigned long)total);

    // 并发跑各组
    NSMutableArray *results = [NSMutableArray array]; // 与 shares 一一对应
    for (NSUInteger i = 0; i < shares.count; i++) [results addObject:[NSNull null]];
    NSLock *rlock = [NSLock new];
    dispatch_group_t grp = dispatch_group_create();
    for (NSUInteger si = 0; si < shares.count; si++) {
        MDPLink *l = shares[si][0];
        NSArray *g = shares[si][1];
        dispatch_group_enter(grp);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSMutableArray *bl = [NSMutableArray arrayWithCapacity:g.count];
            for (NSNumber *k in g) [bl addObject:valid[k.unsignedIntegerValue]];
            NSTimeInterval t0 = [NSDate date].timeIntervalSince1970;
            NSString *e = nil;
            NSArray<NSData *> *res = [l process:slot iv:iv items:bl error:&e];
            NSTimeInterval dt = [NSDate date].timeIntervalSince1970 - t0;
            NSDictionary *rec = nil;
            if (res) {
                NSUInteger sb = 0, rb = 0;
                for (NSData *d in bl) sb += d.length;
                for (NSData *d in res) rb += d.length;
                [self note:l sent:sb recv:rb dt:dt];
                rec = @{ @"res": res };
            } else {
                rec = @{ @"err": e ?: @"?" };
            }
            [rlock lock];
            results[si] = rec;
            [rlock unlock];
            dispatch_group_leave(grp);
        });
    }
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);

    // 回填 + 失败转交 + 兜底
    for (NSUInteger si = 0; si < shares.count; si++) {
        MDPLink *l = shares[si][0];
        NSArray *g = shares[si][1];
        NSDictionary *rec = results[si];
        if (rec[@"res"]) {
            NSArray *res = rec[@"res"];
            for (NSUInteger k = 0; k < g.count; k++)
                out[idx[[g[k] unsignedIntegerValue]].unsignedIntegerValue] = res[k];
            continue;
        }
        l.down = YES;
        [self emit:logf fmt:@"[!] %@ 失败转交: %@", l.name, rec[@"err"]];
        TLDBG(@"%@ 失败转交 %@", l.name, rec[@"err"]);
        NSMutableArray *bl = [NSMutableArray arrayWithCapacity:g.count];
        for (NSNumber *k in g) [bl addObject:valid[k.unsignedIntegerValue]];
        BOOL handed = NO;
        MDPLink *alt = nil;
        for (MDPLink *x in self.links) {
            if (x == l || x.down) continue;
            if (!alt || x.weight > alt.weight) alt = x;
        }
        if (alt) {
            NSString *e2 = nil;
            NSTimeInterval t0 = [NSDate date].timeIntervalSince1970;
            NSArray<NSData *> *res2 = [alt process:slot iv:iv items:bl error:&e2];
            if (res2) {
                NSUInteger sb = 0, rb = 0;
                for (NSData *d in bl) sb += d.length;
                for (NSData *d in res2) rb += d.length;
                [self note:alt sent:sb recv:rb dt:[NSDate date].timeIntervalSince1970 - t0];
                for (NSUInteger k = 0; k < g.count; k++)
                    out[idx[[g[k] unsignedIntegerValue]].unsignedIntegerValue] = res2[k];
                handed = YES;
            } else {
                alt.down = YES;
                [self emit:logf fmt:@"[!] %@ 接管也失败,回退备用通道", alt.name];
            }
        }
        if (!handed) {
            if (!fallback) { if (err) *err = @"链路失败且无兜底"; return nil; }
            NSString *e3 = nil;
            NSArray<NSData *> *fb = fallback(bl, &e3);
            if (!fb) { if (err) *err = e3 ?: @"兜底失败"; return nil; }
            for (NSUInteger k = 0; k < g.count; k++)
                out[idx[[g[k] unsignedIntegerValue]].unsignedIntegerValue] = fb[k];
        }
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
    // 按权重切连续段(单链全量;段下限 1MB,余量归末段)
    NSMutableArray<NSArray *> *ranges = [NSMutableArray array]; // @[link, off, len]
    if (self.links.count == 1) {
        [ranges addObject:@[self.links[0], @0, @(totalSize)]];
    } else {
        double wsum = 0;
        for (MDPLink *l in self.links) wsum += l.weight;
        uint64_t off = 0;
        for (NSUInteger li = 0; li < self.links.count; li++) {
            MDPLink *l = self.links[li];
            if (li == self.links.count - 1) {
                if (totalSize > off) [ranges addObject:@[l, @(off), @(totalSize - off)]];
            } else {
                uint64_t need = (uint64_t)((double)totalSize * l.weight / wsum);
                if (need < 1000000) need = 1000000;
                if (off + need > totalSize) need = totalSize - off;
                if (need > 0) [ranges addObject:@[l, @(off), @(need)]];
                off += need;
            }
        }
    }
    TLDBG(@"取文件 %llu 字节切 %lu 段", totalSize, (unsigned long)ranges.count);
    // 并发取段(各段 pwrite 到自己的偏移,互不干扰)
    NSMutableArray *recs = [NSMutableArray array];
    for (NSUInteger i = 0; i < ranges.count; i++) [recs addObject:[NSNull null]];
    NSLock *rlock = [NSLock new];
    dispatch_group_t grp = dispatch_group_create();
    for (NSUInteger i = 0; i < ranges.count; i++) {
        MDPLink *l = ranges[i][0];
        uint64_t off = [ranges[i][1] unsignedLongLongValue];
        uint64_t len = [ranges[i][2] unsignedLongLongValue];
        dispatch_group_enter(grp);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            NSTimeInterval t0 = [NSDate date].timeIntervalSince1970;
            NSString *e = nil;
            BOOL ok = [l fetchFile:phonePath offset:off length:len toPath:localPath error:&e];
            [self note:l sent:len recv:(ok ? len : 0) dt:[NSDate date].timeIntervalSince1970 - t0];
            [rlock lock];
            recs[i] = ok ? @{ } : @{ @"err": e ?: @"?" };
            [rlock unlock];
            dispatch_group_leave(grp);
        });
    }
    dispatch_group_wait(grp, DISPATCH_TIME_FOREVER);
    // 失败段转交健康链重试一次(pwrite 按偏移,重复写同段无害)
    BOOL all = YES;
    for (NSUInteger i = 0; i < ranges.count; i++) {
        NSDictionary *rec = recs[i];
        if ([rec isKindOfClass:[NSDictionary class]] && rec[@"err"] == nil) continue;
        MDPLink *l = ranges[i][0];
        uint64_t off = [ranges[i][1] unsignedLongLongValue];
        uint64_t len = [ranges[i][2] unsignedLongLongValue];
        [self emit:logf fmt:@"[!] %@ 取段失败(%@),转交健康链重试", l.name, rec[@"err"] ?: @"?"];
        l.down = YES;
        MDPLink *alt = nil;
        for (MDPLink *x in self.links) {
            if (x == l || x.down) continue;
            if (!alt || x.weight > alt.weight) alt = x;
        }
        if (!alt) {
            if (err) *err = [NSString stringWithFormat:@"取段失败且无健康链: %@", rec[@"err"] ?: @"?"];
            all = NO;
            continue;
        }
        NSString *e2 = nil;
        NSTimeInterval t0 = [NSDate date].timeIntervalSince1970;
        BOOL ok = [alt fetchFile:phonePath offset:off length:len toPath:localPath error:&e2];
        [self note:alt sent:len recv:(ok ? len : 0) dt:[NSDate date].timeIntervalSince1970 - t0];
        if (!ok) {
            if (err) *err = e2 ?: @"转交重试也失败";
            all = NO;
        }
    }
    if (all)
        [self emit:logf fmt:@"[*] 双链回传完成 %llu 字节(%lu 段)", totalSize, (unsigned long)ranges.count];
    return all;
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
