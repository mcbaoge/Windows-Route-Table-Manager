# NetVista

NetVista 是一款 Windows 桌面网络控制台工具，提供路由管理、网络拓扑可视化、数据包监控、WFP 防火墙规则管理等功能，帮助网络管理员和运维人员高效诊断和管理 Windows 网络环境。

## 功能

- **路由表管理** — 查看、添加、删除、修改路由条目，支持多网卡跃点数调整
- **网络拓扑** — 自动发现并可视化本地网络拓扑结构
- **数据包监控** — 实时捕获并分析网络数据包
- **WFP 防火墙管理** — 管理 Windows Filtering Platform 过滤规则
- **事件日志** — 记录网络状态变更、路由变化等事件
- **带宽监控** — 实时跟踪各接口带宽使用情况
- **RTT 监控** — 探测目标主机的往返延迟
- **安全监控** — 检测并告警可疑网络活动
- **进程网络监控** — 查看各进程的网络连接状态
- **ETW 追踪** — 基于 Event Tracing for Windows 的低级网络事件采集

## 截图

（待补充）

## 系统要求

- Windows 10 / Windows Server 2016 或更高版本
- Python 3.13+（仅在从源码运行时需要）

## 下载

从 [Releases](https://github.com/mcbaoge/NetVista/releases) 页面下载预编译的 `NetVista.exe`，直接运行即可（无需安装 Python）。

## 从源码构建

```bash
# 克隆仓库
git clone https://github.com/mcbaoge/NetVista.git
cd NetVista

# 创建虚拟环境并安装依赖
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# 运行
python main.py

# 构建单文件可执行程序
pip install pyinstaller
pyinstaller main.spec
```

## 许可证

GNU General Public License v3.0 — 详见 [LICENSE](LICENSE)。

你可以自由使用本软件进行任何合法活动（包括使用它帮别人修网络并收取服务费），但禁止将本软件或其修改版本闭源倒卖或用作商业闭源产品的组成部分。
