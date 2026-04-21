# Maac4ML

Maac4ML: **Multi-authority Attribute-Based Access Control for Privacy-Preserving Machine Learning Deployment**

本仓库包含论文实验部分的代码实现，主要分为两类：

1. **基础密码学操作耗时测量**
   - 合数阶双线性群参数生成
   - 群元素大小统计
   - `G` 上指数运算、`GT` 上指数运算、pairing 的运行时间测量

2. **Maac4ML 原型实现**
   - MABIPFE 的核心流程：`GSetup / AASetup / KGen / Enc / Dec`
   - Maac4ML 的原型级 demo
   - 面向审稿意见补充的系统级指标测量：在线时延、通信开销、存储开销、不同 authority 数量下的可扩展性等
   - 有界离散对数恢复 demo：在**8-bit 向量范围**下通过**穷举法**恢复最终内积值

---

## 1. 仓库内容概览

本仓库的代码用于支撑论文中的两部分实验：

### (A) MABIPFE 基础实验
用于生成论文中关于以下内容的数据：

- 合数阶 / 素数阶群的基础操作耗时
- 元素大小统计
- 理论复杂度中的参数校准（calibration）
- `Enc` / `Dec` 的数值模拟与原型测量参考

### (B) Maac4ML 原型实验
用于生成论文中关于以下内容的数据：

- 公共参数生成时间（PP generation）
- 多 authority 的 `AASetup`、`KGen`、`Dec` 时间
- 端到端在线时延（online end-to-end）
- ciphertext / public key / request / response 的字节数
- authority 数量变化下的系统扩展性
- 授权解密正确性与未授权拒绝行为

---

## 2. 代码实现特点

### 2.1 合数阶公共参数实现
仓库中包含基于 JPBC 的合数阶双线性群公共参数实现，用于：

- 生成 composite-order pairing parameters
- 测量 `G`、`GT`、`Z_N` 元素大小
- 测量基础群运算和 pairing 的平均耗时

这部分代码主要服务于论文实验中对基础密码学操作的时间与空间校准。

### 2.2 MABIPFE 原型
仓库实现了论文中的 MABIPFE 原型流程，包括：

- `GSetup`
- `AASetup`
- `KGen`
- `Enc`
- `Dec`

其中：

- access policy 采用原型实现可处理的结构进行演示
- prototype 重点在于**功能验证**和**系统级开销测量**
- 解密阶段保留了最终的 bounded-range inner-product recovery 过程

### 2.3 8-bit 向量与穷举恢复
为了与论文实验设置保持一致，原型中**故意将向量坐标限制在 8-bit 范围内**：

\[
[-128, 127]
\]

这样，在向量维度为 \(s\) 时，内积值满足有界范围：

\[
[-s \cdot 127 \cdot 127,\; s \cdot 127 \cdot 127]
\]

因此可以在解密末尾通过**穷举法**恢复对应的离散对数，从而得到最终的内积值。这一实现用于演示论文中 bounded-range recovery 的可行性，而不是面向大范围数值的高效离散对数算法。

---

## 3. 论文实验对应关系

本仓库代码对应论文实验中的以下部分：

### 3.1 基础操作与参数校准
对应论文中：

- 群元素大小统计
- `G` / `GT` 上指数运算耗时
- pairing 耗时
- prime-order 与 composite-order 的时间/空间校准表

### 3.2 MABIPFE 实验
对应论文中：

- `PK` / `CT` / `AASetup` / `KGen` / `Enc` / `Dec` 的理论与数值分析
- 不同方案在 MABIPFE 层面的对比

### 3.3 Maac4ML 原型实验
对应论文中：

- prototype-level metrics
- online latency
- communication overhead
- ciphertext / model size
- authority scaling
- authorized correctness / unauthorized rejection
- bounded exhaustive-search recovery demo

---

## 4. 运行环境

建议环境如下：

- **Java**: 8 或更高版本
- **JPBC**
- 支持 JPBC 所需的 pairing 参数生成组件
- Linux / macOS / Windows 均可，论文实验环境为 Ubuntu

如果你使用 IDE（如 IntelliJ IDEA / Eclipse），请确保：

- 已正确导入 JPBC 依赖
- 工程的 package 路径与源码中的 package 声明一致
- 运行配置指向对应的 main 类

---

## 5. 如何运行

### 5.1 基础操作耗时测试
运行相应的公共参数测试类，可得到：

- `PP generation`
- `G exp`
- `GT exp`
- `pairing`
- `|G|`, `|GT|`, `|Z_N|`

这些输出可用于论文中基础时间/空间校准实验。

### 5.2 MABIPFE / Maac4ML 原型 demo
运行 Maac4ML 的 demo 主类，可得到类似如下输出：

- 输入向量、pivotal input、pivotal weight
- plaintext inner product
- recovered inner product
- authorized / unauthorized behavior
- prototype-level metrics
- authority scaling results

输出中通常包括：

- `PP generation`
- `AASetup total / avg`
- `Model publishing / Enc`
- `KGen total / avg / max`
- `Dec time`
- `Online end-to-end`
- request / response bytes
- ciphertext bytes
- authority scaling

### 5.3 解密分项时间
部分版本的 demo 还会输出：

- `Dec breakdown: core=...`
- `DLog recovery=...`
- `total=...`

其中：

- `core` 表示受保护内积的密码学恢复过程
- `DLog recovery` 表示最终 bounded-range 穷举恢复离散对数的时间
- `total` 为完整的 prototype-level decryption time

---

## 6. 输出指标说明

### 6.1 时间指标
- **PP generation**：公共参数生成时间
- **AASetup total / avg**：authority 初始化总时间 / 平均单 authority 时间
- **Model publishing / Enc**：模型发布阶段的加密时间
- **KGen total / avg / max**：属性密钥生成总时间 / 平均时间 / 最大单 authority 时间
- **Dec time**：完整解密时间
- **Online end-to-end**：单次在线推理端到端时间

### 6.2 通信与存储指标
- **ciphertext bytes**：密文字节数
- **published model bytes**：发布模型整体字节数估计
- **authority PK bytes**：authority 公钥总开销
- **request / response bytes**：在线请求和响应的通信开销

### 6.3 功能性指标
- **Recovered inner product == Plaintext inner product**
- **Authorized decryption ok = true**
- **Unauthorized decryption rejected = true**

这些指标用于验证：

- 受保护内积恢复的正确性
- access-control enforcement 的有效性
- prototype 行为是否与论文描述一致

---

## 7. 与论文中的实现假设保持一致的设置

为方便复现实验，代码中采用了与论文一致的若干简化/原型设置：

1. **向量坐标限制在 8-bit 范围内**
2. **最终内积恢复采用 bounded exhaustive search**
3. **prototype 的主要目标是测量系统级指标，而不是工程化优化**
4. **authority 数量变化主要用于观察时延、通信与 ciphertext size 的扩展趋势**
5. **`KGen` 在现实部署中可并行执行，因此论文更关注 per-authority 平均开销**

---

## 8. 结果解释建议

阅读实验结果时，可参考以下理解方式：

- `Enc` 主要反映模型发布阶段的**一次性离线开销**
- `Dec` 和 `KGen` 更直接影响**重复在线使用时的实际延迟**
- 在多 authority 场景下，`KGen total` 是总工作量，而 `KGen avg/authority` 更接近现实并行部署中的单 authority 延迟贡献
- bounded exhaustive-search 的恢复时间是 prototype 中显式实现的一部分，应与核心密码学恢复过程区分理解

---

## 9. 复现实验时的注意事项

1. **不同机器上运行时间会有明显波动**
   - pairing-based code 对硬件、JVM、负载状态较敏感
   - 建议多次运行后取平均值

2. **首次运行通常比后续运行更慢**
   - 可能受到 JVM 预热、参数生成、缓存等因素影响

3. **穷举恢复开销与向量维度和坐标范围直接相关**
   - 本仓库的 demo 只针对论文中的 bounded-range setting

4. **本仓库以论文原型验证为目标**
   - 代码更强调与论文实验设置一致
   - 不以工业级性能优化为首要目标

---

## 10. 引用与说明

如果你使用了本仓库中的代码或实验结果，请结合对应论文正文中的实验章节进行说明。  
本仓库中的实现主要用于：

- 支撑论文中的 cryptographic calibration
- 支撑 MABIPFE prototype evaluation
- 支撑 Maac4ML system-level prototype metrics

---

## 11. 联系方式

如对代码或论文实验设置有疑问，请联系论文作者。

