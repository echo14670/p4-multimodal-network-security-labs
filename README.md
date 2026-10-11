# P4 多模态网络内生安全实验

本仓库整理前两次实验的代码、操作记录和运行证据。第三次实验将在同一 Git 仓库中继续开发。

## 实验阶段

- `class1/`：统一 P4 虚拟机环境、官方 basic 自检说明，以及未修改的三模态原始 Demo 基线。
- `class2/`：在基线之上完成 M1-M4，包括 PolyShim、Parser 分支、序号与 CRC 生成、multicast group 10、IPv4/IPv6/Source Routing 三种外层封装和双向路径验证。

## 目录说明

```text
class1/
  baseline-demo/                三模态原始 Demo
  evidence/                     基线回归与参考结果
  class1_env_record.sh          VM 环境记录脚本
  path-summary.txt              路径证据模板

class2/
  polymorphic-scheduling/       第二次实验 P4、控制器和测试脚本
  evidence/                     pcap、日志、终端截图和过程记录
  packet-summary.txt            第二次实验结果说明
```

## 第二次实验完成范围

- 一次主机输入在 S1 或 S2 的 PRE 中复制为三份。
- 三份副本共享相同 `sequence_number` 和 `source_crc32`。
- 模态分别映射为 IPv4 `protocol=253`、IPv6 `nextHdr=253`、SR `EtherType=0x1234`。
- 正向和反向都验证了三种封装和三条物理路径。
- IPv4、IPv6、ARP 和原始 Source Routing 回归功能保持正常。
- M5/M6 属于第三次实验，不在第二次提交范围内。

## 运行入口

第一次实验说明：

```text
class1/第1次实验_环境配置与运行指南.md
```

第二次实验：

```bash
cd class2/polymorphic-scheduling
make
# 另一个终端
python3 mycontroller.py
```

运行前按课程材料加载 P4 虚拟机环境；仓库不提交 `build/`、`logs/`、顶层 `pcaps/` 和 Python 缓存。

## 版本标记

- `class1-baseline`：第一次实验基线阶段。
- `class2-multicast`：第二次实验 M1-M4 阶段。

第一次作业目录中保留了可复现指南、环境记录脚本、原始 Demo 和回归证据；课程要求的 VM 环境截图与 `environment.txt` 如未随原工作目录导出，可在虚拟机中补交时不改变本仓库的基线代码。
