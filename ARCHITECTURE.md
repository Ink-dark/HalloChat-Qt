# 架构设计文档

## 不可逆架构决策

### 1. 协议层
- **二进制协议优先**：淘汰JSON-over-WebSocket方案，采用自定义二进制协议提升传输效率
- **小端序强制统一**：所有数值类型采用小端序编码，解决跨设备兼容性问题
- **无向后兼容承诺**：协议版本严格匹配，不提供向下兼容支持

### 2. 设备分层
| 设备等级 | RAM阈值 | 加密方案 | 消息限制 | 媒体支持 |
|----------|---------|----------|----------|----------|
| 低功耗   | <100MB  | XTEA     | 128B     | ❌       |
| 移动设备 | 100-1GB | CHACHA20 | 1KB      | ✅       |
| 桌面设备 | >1GB    | AES256-GCM | 10MB    | ✅       |

### 3. 安全红线
- **传输安全**：禁用TLS 1.2及以下版本，强制使用TLS 1.3
- **存储安全**：消息内容全程加密存储，无明文落地
- **设备策略**：不允许安全降级，高等级设备不可切换至低等级加密方案

## 核心模块交互
1. **领域模型层**：User/Message/DeviceProfile提供统一数据结构和序列化接口
2. **协议层**：BinaryEncoder负责消息的二进制编解码和CRC32校验
3. **设备管理层**：DeviceFactory根据硬件检测结果动态创建对应ProtocolHandler
4. **资源监控**：实时采集系统指标，动态调整功能开关

## 性能指标
- 低功耗设备（树莓派Zero）：协议解析速度 ≥1000 msg/s
- 内存占用：低功耗设备协议处理器 ≤8MB
- 加密性能：XTEA加密吞吐量 ≥50KB/s（树莓派Zero环境）