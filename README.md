# DHCP Tool — Windows DHCP 分配工具

一个简单易用的 Windows DHCP 服务分配工具，双击即可运行。

## 功能

- **网卡选择** — 自动枚举本机所有可用网卡，下拉选择
- **IP 池配置** — 设置起始 IP、结束 IP、子网掩码、网关、DNS、租约时间
- **一键启停** — 点击"启动 DHCP"即刻运行，支持随时停止
- **防火墙自动配置** — 启动时自动添加 Windows 防火墙入站规则（UDP 67/68），状态栏实时显示放行状态
- **客户端列表** — 实时刷新已分配客户端（MAC 地址 / IP 地址 / 主机名 / 剩余租约）
- **完整 DHCP 协议** — 基于 RFC 2131 实现，支持 Discover → Offer → Request → Ack 完整流程

## 使用方法

1. **下载** — 从 [Releases](https://github.com/lll031/Windows-DHCP-Tool/releases) 获取最新版 `DHCPTool.exe`
2. **运行** — 双击 `DHCPTool.exe`（首次运行会弹出 UAC 提示，点"是"授予管理员权限）
3. **选择网卡** — 下拉选择你需要开放 DHCP 服务的网卡（建议选择内网网卡）
4. **配置网段** — 填写 IP 分配范围，默认值通常可直接使用
5. **启动** — 点击"▶ 启动 DHCP"，防火墙规则自动配置，状态栏提示"防火墙: 已放行 UDP 67/68"
6. **其他设备接入同网段即可自动获取 IP**

## 开发

```bash
# 克隆仓库
git clone https://github.com/lll031/Windows-DHCP-Tool.git
cd Windows-DHCP-Tool

# 创建虚拟环境（Python 3.8+）
python -m venv .venv
.venv\Scripts\activate

# 安装依赖
pip install customtkinter psutil pyinstaller

# 运行调试
python dhcptool\main.py

# 打包为 exe
pyinstaller --onefile --windowed --uac-admin --name DHCPTool --collect-all customtkinter --hidden-import psutil dhcptool\main.py
```

## 系统要求

- **操作系统**: Windows 10 / Windows 11（64 位）
- **权限**: 管理员权限（需要绑定 UDP 端口 67）
- **依赖**: 无需额外安装，单文件 exe 开箱即用

## 常见问题

**Q: 为什么需要管理员权限？**
DHCP 服务的标准端口 UDP 67 需要管理员权限才能绑定，exe 已内嵌 UAC 清单，双击会自动申请权限。

**Q: 客户端无法获取 IP？**
- 检查状态栏是否显示"防火墙: 已放行 UDP 67/68"
- 确认客户端设备与运行 DHCP 工具的网卡在同一网段
- 检查无线路由器/交换机是否启用了 DHCP Snooping

## 许可证

MIT License
