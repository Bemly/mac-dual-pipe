#import "MDPLink.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// 线上常量(与对端实现逐字节对齐;改动需两端同步,见 README)
static const uint32_t kReqMagic  = 0x41443031; // 'AD01'
static const uint32_t kRespMagic = 0x41443032; // 'AD02'
static const uint8_t kCmdM = 0x4D;             // 批量变换
static const uint8_t kCmdE = 0x45;             // 回显
static const uint8_t kCmdQ = 0x51;             // 断开
static const uint8_t kCmdV = 0x56;             // 代号问询
static const uint8_t kCmdF = 0x46;             // 取文件:path+offset+length → 原样 length 字节

static const NSTimeInterval kConnTimeout = 5;
static const NSTimeInterval kIoTimeout = 120;

static BOOL TLDebugOn(void) {
    static BOOL v;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ v = getenv("DUALPIPE_DEBUG") != NULL; });
    return v;
}
#define TLDBG(fmt, ...) do { if (TLDebugOn()) NSLog(@"[TL] " fmt, ##__VA_ARGS__); } while (0)

static void PutU32(NSMutableData *d, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    [d appendBytes:b length:4];
}

static void PutU64(NSMutableData *d, uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - i * 8));
    [d appendBytes:b length:8];
}

static uint32_t GetU32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

// ---- socket 原语 ----

static int TlConnectOnce(const char *ip, int port, NSString **err);

static int TlConnect(const char *ip, int port, NSString **err) {
    // 瞬断 WiFi 下首次 connect 常报 No route to host,重试 3 次(每次间隔 1s);
    // 真挂(地址非法除外)最多多花约 2s + 各次自带超时。
    NSString *lastErr = nil;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) [NSThread sleepForTimeInterval:1.0];
        int fd = TlConnectOnce(ip, port, &lastErr);
        if (fd > 2) return fd;
        // fd==0..2:标准流被占用(见 TlConnectOnce 注释),绝不 close,直接失败
        if (fd >= 0) { lastErr = @"socket 落到标准流(启动 fd 保护缺失)"; break; }
        if (lastErr && [lastErr rangeOfString:@"地址非法"].location != NSNotFound) break;
    }
    if (err) *err = lastErr;
    return -1;
}

static int TlConnectOnce(const char *ip, int port, NSString **err) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { if (err) *err = @"建 socket 失败"; return -1; }
    if (fd <= 2) {
        // 0/1/2 是标准流:正常进程 socket 不可能落在这里;落在这里说明启动时
        // stdin 被关过(旧版 dealloc-close(0) 级联)。绝不能 close(经 launchd 启动
        // 时 fd0 被 guard,close 即 EXC_GUARD)。直接失败不接管,让调用方走兜底。
        if (err) *err = @"socket 落到标准流(启动 fd 保护缺失)";
        return fd; // 由调用方判 <=2 拒绝且不 close,泄一个 fd 保进程不死
    }
    int one = 1;
    // 发包到已断连接默认发 SIGPIPE 直接打死进程;改走 EPIPE 错误返回(故障转交就靠它)
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        if (fd > 2) close(fd);
        if (err) *err = @"地址非法";
        return -1;
    }
    int r = connect(fd, (struct sockaddr *)&a, sizeof(a));
    if (r < 0 && errno != EINPROGRESS) {
        NSString *e = [NSString stringWithFormat:@"connect: %s", strerror(errno)];
        if (fd > 2) close(fd);
        if (err) *err = e;
        return -1;
    }
    if (r < 0) {
        fd_set w;
        FD_ZERO(&w);
        FD_SET(fd, &w);
        struct timeval tv = { (int)kConnTimeout, 0 };
        r = select(fd + 1, NULL, &w, NULL, &tv);
        if (r <= 0) {
            if (fd > 2) close(fd);
            if (err) *err = @"connect 超时";
            return -1;
        }
        int soErr = 0;
        socklen_t n = sizeof(soErr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &n);
        if (soErr) {
            NSString *e = [NSString stringWithFormat:@"connect: %s", strerror(soErr)];
            if (fd > 2) close(fd);
            if (err) *err = e;
            return -1;
        }
    }
    fcntl(fd, F_SETFL, fl);
    struct timeval tv2 = { (int)kIoTimeout, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv2, sizeof(tv2));
    return fd;
}

static BOOL TlSendAll(int fd, const uint8_t *p, size_t n, NSString **err) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = send(fd, p + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (err) *err = [NSString stringWithFormat:@"send: %s", strerror(errno)];
            return NO;
        }
        off += (size_t)r;
    }
    return YES;
}

static BOOL TlRecvFill(int fd, uint8_t *p, size_t n, NSString **err) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, p + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (err) *err = [NSString stringWithFormat:@"recv: %s", strerror(errno)];
            return NO;
        }
        if (r == 0) {
            if (err) *err = @"对端关闭";
            return NO;
        }
        off += (size_t)r;
    }
    return YES;
}

// 应答头 9B:magic u32 + status u8 + len/nOut u32
static BOOL TlReadHead(int fd, uint32_t *magic, uint8_t *status, uint32_t *num, NSString **err) {
    uint8_t h[9];
    if (!TlRecvFill(fd, h, 9, err)) return NO;
    if (magic) *magic = GetU32(h);
    if (status) *status = h[4];
    if (num) *num = GetU32(h + 5);
    return YES;
}

#pragma mark - 单链

@interface MDPLink ()
@property (nonatomic, assign) int fd;
@property (nonatomic, strong) NSLock *mx;
@property (nonatomic, assign) BOOL shut;
@end

@implementation MDPLink

- (nullable instancetype)initWithName:(NSString *)name
                                 addr:(NSString *)addr
                                 port:(int)port
                                error:(NSString **)err {
    if ((self = [super init])) {
        // 先落默认值:连接失败 return nil 会走 dealloc→close,此时 _fd 必须是 -1
        // 否则零初始化的 0 会被当有效 fd close(0),经 open/launchd 启动即 EXC_GUARD
        // (2026-09-14 实录:wifi 超时→init nil→dealloc close(0)→GUI 崩)。
        _fd = -1;
        _mx = [NSLock new];
        _weight = 1.0;
        NSString *e = nil;
        int fd = TlConnect(addr.UTF8String, port, &e);
        if (fd <= 2) { if (err) *err = e; return nil; }
        _name = [name copy];
        _fd = fd;
        TLDBG(@"链路 %@ %@:%d 已连", name, addr, port);
    }
    return self;
}

- (BOOL)echo:(NSData *)data error:(NSString **)err {
    [self.mx lock];
    BOOL ok = NO;
    @try {
        if (self.shut) { if (err) *err = @"已关闭"; return NO; }
        NSMutableData *body = [NSMutableData data];
        PutU32(body, kReqMagic);
        [body appendBytes:&kCmdE length:1];
        PutU32(body, (uint32_t)data.length);
        if (data.length) [body appendData:data];
        NSString *e = nil;
        if (!TlSendAll(self.fd, body.bytes, body.length, &e)) { if (err) *err = e; return NO; }
        uint32_t magic = 0, ln = 0;
        uint8_t st = 0;
        if (!TlReadHead(self.fd, &magic, &st, &ln, &e)) { if (err) *err = e; return NO; }
        if (magic != kRespMagic) { if (err) *err = @"协议魔数错位"; return NO; }
        if (st != 0) { if (err) *err = @"回显被拒"; return NO; }
        NSMutableData *back = [NSMutableData dataWithLength:ln];
        if (ln && !TlRecvFill(self.fd, back.mutableBytes, ln, &e)) { if (err) *err = e; return NO; }
        ok = [back isEqualToData:data];
        if (!ok && err) *err = @"回环不一致";
    } @finally {
        [self.mx unlock];
    }
    return ok;
}

- (nullable NSString *)queryGenWithError:(NSString **)err {
    [self.mx lock];
    NSString *gen = nil;
    @try {
        if (self.shut) { if (err) *err = @"已关闭"; return nil; }
        uint8_t req[5];
        req[0] = (uint8_t)(kReqMagic >> 24); req[1] = (uint8_t)(kReqMagic >> 16);
        req[2] = (uint8_t)(kReqMagic >> 8); req[3] = (uint8_t)kReqMagic; req[4] = kCmdV;
        NSString *e = nil;
        if (!TlSendAll(self.fd, req, 5, &e)) { if (err) *err = e; return nil; }
        uint32_t magic = 0, ln = 0;
        uint8_t st = 0;
        if (!TlReadHead(self.fd, &magic, &st, &ln, &e)) { if (err) *err = e; return nil; }
        if (magic != kRespMagic) { if (err) *err = @"协议魔数错位"; return nil; }
        if (st != 0) { if (err) *err = @"代号被拒"; return nil; }
        NSMutableData *back = [NSMutableData dataWithLength:ln];
        if (ln && !TlRecvFill(self.fd, back.mutableBytes, ln, &e)) { if (err) *err = e; return nil; }
        gen = [[NSString alloc] initWithData:back encoding:NSASCIIStringEncoding];
    } @finally {
        [self.mx unlock];
    }
    return gen;
}

- (nullable NSArray<NSData *> *)process:(uint32_t)slot
                                     iv:(NSData *)iv
                                  items:(NSArray<NSData *> *)cts
                                  error:(NSString **)err {
    [self.mx lock];
    NSArray<NSData *> *out = nil;
    @try {
        if (self.shut) { if (err) *err = @"已关闭"; return nil; }
        if (iv.length != 16) { if (err) *err = @"IV 非 16B"; return nil; }
        NSUInteger total = 0;
        for (NSData *c in cts) total += c.length;
        NSMutableData *body = [NSMutableData dataWithCapacity:29 + total + cts.count * 4];
        PutU32(body, kReqMagic);
        [body appendBytes:&kCmdM length:1];
        PutU32(body, slot);
        [body appendData:iv];
        PutU32(body, (uint32_t)cts.count);
        for (NSData *c in cts) PutU32(body, (uint32_t)c.length);
        PutU32(body, (uint32_t)total);
        for (NSData *c in cts) if (c.length) [body appendData:c];
        NSString *e = nil;
        if (!TlSendAll(self.fd, body.bytes, body.length, &e)) { if (err) *err = e; return nil; }
        // M 应答无总长前缀:magic/status/nOut + 条目(按条目数读完即止,不依赖总长)
        uint32_t magic = 0, nOut = 0;
        uint8_t st = 0;
        if (!TlReadHead(self.fd, &magic, &st, &nOut, &e)) { if (err) *err = e; return nil; }
        if (magic != kRespMagic) { if (err) *err = @"协议魔数错位"; return nil; }
        if (st != 0) { if (err) *err = @"批量被拒"; return nil; }
        if (nOut != cts.count) {
            if (err) *err = [NSString stringWithFormat:@"返回包数对不上(%u/%lu)", nOut, (unsigned long)cts.count];
            return nil;
        }
        NSMutableArray<NSData *> *res = [NSMutableArray arrayWithCapacity:cts.count];
        for (NSUInteger i = 0; i < cts.count; i++) {
            uint8_t lb[4];
            if (!TlRecvFill(self.fd, lb, 4, &e)) { if (err) *err = e; return nil; }
            uint32_t m = GetU32(lb);
            if (m == 0) { [res addObject:[NSData data]]; continue; }
            NSMutableData *one = [NSMutableData dataWithLength:m];
            if (!TlRecvFill(self.fd, one.mutableBytes, m, &e)) { if (err) *err = e; return nil; }
            [res addObject:one];
        }
        out = res;
    } @finally {
        [self.mx unlock];
    }
    return out;
}

// F=取文件:请求 path+offset u64+length u64,应答头(magic+status)后对端原样流 length 字节
// (零编码);本侧边收边 pwrite 到 localPath 的 offset 起——双链各取一段,按偏移拼成整文件。
- (BOOL)fetchFile:(NSString *)phonePath
           offset:(uint64_t)offset
           length:(uint64_t)length
           toPath:(NSString *)localPath
            error:(NSString **)err {
    [self.mx lock];
    @try {
        if (self.shut) { if (err) *err = @"已关闭"; return NO; }
        NSData *pb = [phonePath dataUsingEncoding:NSUTF8StringEncoding];
        NSMutableData *body = [NSMutableData data];
        PutU32(body, kReqMagic);
        [body appendBytes:&kCmdF length:1];
        PutU32(body, (uint32_t)pb.length);
        [body appendData:pb];
        PutU64(body, offset);
        PutU64(body, length);
        NSString *e = nil;
        if (!TlSendAll(self.fd, body.bytes, body.length, &e)) { if (err) *err = e; return NO; }
        uint32_t magic = 0, ln = 0;
        uint8_t st = 0;
        if (!TlReadHead(self.fd, &magic, &st, &ln, &e)) { if (err) *err = e; return NO; }
        if (magic != kRespMagic) { if (err) *err = @"协议魔数错位"; return NO; }
        if (st != 0) { if (err) *err = @"取文件被拒(对端打开/寻址失败)"; return NO; }
        int lfd = open(localPath.UTF8String, O_WRONLY);
        if (lfd < 0) { if (err) *err = @"本地成品文件打不开"; return NO; }
        if (lfd <= 2) { if (err) *err = @"本地文件落到标准流(启动 fd 保护缺失)"; return NO; }
        static const size_t kBuf = 262144;
        uint8_t *buf = (uint8_t *)malloc(kBuf);
        if (!buf) { if (lfd > 2) close(lfd); if (err) *err = @"内存不足"; return NO; }
        uint64_t got = 0;
        BOOL ok = YES;
        while (ok && got < length) {
            size_t want = (size_t)MIN((uint64_t)kBuf, length - got);
            ssize_t r = recv(self.fd, buf, want, 0);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) {
                if (err) *err = r == 0 ? @"对端提前断流" : [NSString stringWithFormat:@"recv: %s", strerror(errno)];
                ok = NO;
                break;
            }
            size_t done = 0;
            while (ok && done < (size_t)r) {
                ssize_t w = pwrite(lfd, buf + done, (size_t)r - done, (off_t)(offset + got + done));
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) { if (err) *err = @"pwrite 失败"; ok = NO; break; }
                done += (size_t)w;
            }
            got += (uint64_t)r;
        }
        free(buf);
        if (lfd > 2) close(lfd);
        if (!ok) return NO;
        if (got != length) { if (err) *err = @"收流长度不齐"; return NO; }
    } @finally {
        [self.mx unlock];
    }
    return YES;
}

- (void)close {
    NSLock *mx = _mx;
    if (mx) [mx lock];
    // _fd<=2 永不 close:0/1/2 是标准流(失败路径的 -1 与旧对象的 0 都落在这里);
    // close(0) 在经 open/launchd 启动时即 EXC_GUARD,宁可泄也不碰。
    if (!self.shut && _fd > 2) {
        uint8_t q[5];
        q[0] = (uint8_t)(kReqMagic >> 24); q[1] = (uint8_t)(kReqMagic >> 16);
        q[2] = (uint8_t)(kReqMagic >> 8); q[3] = (uint8_t)kReqMagic; q[4] = kCmdQ;
        TlSendAll(_fd, q, 5, NULL);   // 尽力而为,失败直接关
        close(_fd);
        _fd = -1;
    } else if (_fd >= 0 && _fd <= 2) {
        _fd = -1;
    }
    self.shut = YES;
    if (mx) [mx unlock];
}

- (void)dealloc { [self close]; }

@end
