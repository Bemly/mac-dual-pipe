#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// TwinLink —— 双链二进制直传传输层(macOS 侧,纯 Objective-C,零第三方依赖)。
//
// 线上协议(全大端,大流量无文本编码开销):
//   请求 MAGIC'AD01'+cmd;M=批量:slot u32+iv16B+nItems u32+lens[n] u32+totalCt u32+ct;
//   E=回显:len u32+bytes;Q=断开。
//   应答 MAGIC'AD02'+status u8(0=ok)+M:nOut u32+[len u32+bytes]* / E:len+bytes。
// 另有两个 socket 内建查询:V=代号问询(识破连到旧实例,载荷为代号原文)。
//
// 本库只实现传输与调度:批量条目的"变换"语义由对端定义,slot 的登记方式由调用方
// 经 control 通道自定。本库不感知任何业务,只保证字节进出一致。

@interface TLLink : NSObject

- (nullable instancetype)initWithName:(NSString *)name
                                addr:(NSString *)addr
                                port:(int)port
                               error:(NSString * _Nullable * _Nullable)err;

// 回显往返(内容逐字节比对);代号问询(返回对端代号原文)
- (BOOL)echo:(NSData *)data error:(NSString * _Nullable * _Nullable)err;
- (nullable NSString *)queryGenWithError:(NSString * _Nullable * _Nullable)err;

// 批量变换:iv16B + 输入表 → 同序输出表(与输入等长)
- (nullable NSArray<NSData *> *)process:(uint32_t)slot
                                     iv:(NSData *)iv
                                  items:(NSArray<NSData *> *)cts
                                  error:(NSString * _Nullable * _Nullable)err;

- (void)close;   // 发 Q 后关连接,幂等

@property (nonatomic, readonly) NSString *name;
@property (nonatomic, assign) double weight;   // 吞吐估计(字节/秒,EWMA 维护)
@property (nonatomic, assign) BOOL down;       // 熔断/故障标记
@property (nonatomic, assign) NSTimeInterval resumeAt;

@end

NS_ASSUME_NONNULL_END
