# Apriori 自动签到脚本

- 这个Python脚本用于自动完成Apriori平台的签到流程，包括获取nonce、钱包签名、登录、与Monad合约交互以及最终的签到提交。
- 如需使用eth主网进行签到请更改配置文件中的MONAD_RPC为eth主网rpc，更改CHAIN_ID为eth主网id

本项目包含两个脚本：
- `apriori_checkin.py`: 单钱包签到脚本
- `multi_wallet_checkin.py`: 多钱包签到脚本，支持每个钱包使用不同的代理

## 功能特点

### 共同特点
- 自动获取nonce并构建签名消息
- 使用EVM钱包私钥进行消息签名
- 自动登录获取access_token
- 与Monad测试网合约进行交互
- 提交交易哈希完成签到
- 内置重试机制，提高稳定性
- 详细的日志输出和错误诊断
- 增强的错误处理和调试功能
- 多种配置方式：环境变量、JSON配置文件、命令行参数

### 多钱包脚本特点
- 支持同时处理多个钱包的签到
- 每个钱包可配置独立的HTTP/SOCKS代理
- 多线程并发处理，提高效率
- 可配置钱包处理间隔，避免请求过于集中
- 支持从CSV文件批量导入钱包
- 详细的执行结果统计和日志记录
- 自动保存执行结果到JSON文件

## 安装依赖

在使用脚本前，请确保安装以下依赖：

```bash
pip install -r requirements.txt
```

或者手动安装：

```bash
pip install requests web3 eth-account python-dotenv
```

## 配置方法

### 单钱包脚本配置

有多种方式配置单钱包脚本：

#### 1. 环境变量配置（推荐）

1. 复制`.env.example`文件为`.env`
2. 编辑`.env`文件，填入你的钱包地址和私钥
3. 请注意你钱包地址的大小写

```
WALLET_ADDRESS=你的钱包地址
PRIVATE_KEY=你的私钥
```

#### 2. JSON配置文件

1. 复制`config.example.json`文件为`config.json`
2. 编辑`config.json`文件，填入你的配置信息

### 多钱包脚本配置

多钱包脚本支持两种配置方式：

#### 1. JSON配置文件

1. 编辑`multi_wallet_config.json`文件，填入全局配置和钱包列表

```json
{
  "network": {
    "monad_rpc": "https://rpc.ankr.com/monad_testnet",
    "chain_id": 10143
  },
  "contract": {
    "address": "0x703e753e9a2aca1194ded65833eaec17dcfeac1b",
    "method": "0x183ff085"
  },
  "settings": {
    "verbose": false,
    "threads": 3,
    "delay": 5
  },
  "wallets": [
    {
      "address": "0x钱包地址1",
      "private_key": "钱包私钥1",
      "proxy": "http://用户名:密码@代理服务器:端口"
    },
    {
      "address": "0x钱包地址2",
      "private_key": "钱包私钥2",
      "proxy": "http://127.0.0.1:7890"
    },
    {
      "address": "0x钱包地址3",
      "private_key": "钱包私钥3",
      "proxy": null
    }
  ]
}
```

#### 2. CSV文件配置

1. 创建一个CSV文件，包含钱包地址、私钥和代理信息

```csv
address,private_key,proxy
0x钱包地址1,钱包私钥1,http://用户名:密码@代理服务器:端口
0x钱包地址2,钱包私钥2,http://127.0.0.1:7890
0x钱包地址3,钱包私钥3,
0x钱包地址4,钱包私钥4,socks5://127.0.0.1:1080
```

2. 使用`--csv`参数指定CSV文件路径

```json
{
  "wallet": {
    "address": "你的钱包地址",
    "private_key": "你的私钥"
  },
  "settings": {
    "verbose": true
  }
}
```

### 3. 命令行参数配置

```bash
python apriori_checkin.py -w 你的钱包地址 -k 你的私钥 -v
```

参数说明：
- `-w, --wallet`: 钱包地址
- `-k, --key`: 钱包私钥
- `-r, --rpc`: Monad RPC地址
- `-c, --contract`: 合约地址
- `-m, --method`: 合约方法
- `-i, --chainid`: 链ID
- `-v, --verbose`: 显示详细日志
**配置优先级**: 命令行参数 > 环境变量 > JSON配置文件 > 默认值
## 使用方法

### 单钱包脚本使用

#### 基本使用

```bash
python apriori_checkin.py
```

#### 显示详细日志

```bash
python apriori_checkin.py -v
```

#### 指定钱包地址和私钥

```bash
python apriori_checkin.py -w 0x你的钱包地址 -k 你的私钥
```

### 多钱包脚本使用

#### 使用JSON配置文件

```bash
python multi_wallet_checkin.py
```

#### 使用CSV文件

```bash
python multi_wallet_checkin.py --csv wallets.csv
```

#### 指定线程数和延迟

```bash
python multi_wallet_checkin.py --threads 5 --delay 3
```

#### 显示详细日志

```bash
python multi_wallet_checkin.py -v
```

#### 完整参数说明

```bash
python multi_wallet_checkin.py -h
```

输出：
```
usage: multi_wallet_checkin.py [-h] [-c CONFIG] [--csv CSV] [-r RPC] [--contract CONTRACT] [--method METHOD] [--chainid CHAINID] [-v] [-t THREADS] [--delay DELAY]

Apriori多钱包自动签到脚本

options:
  -h, --help            显示帮助信息
  -c CONFIG, --config CONFIG
                        配置文件路径
  --csv CSV             CSV钱包文件路径
  -r RPC, --rpc RPC     Monad RPC地址
  --contract CONTRACT   合约地址
  --method METHOD       合约方法
  --chainid CHAINID     链ID
  -v, --verbose         显示详细日志
  -t THREADS, --threads THREADS
                        并发处理的线程数
  --delay DELAY         每个钱包处理之间的延迟(秒)
```

## 配置说明

脚本支持以下配置项：

| 配置项 | 环境变量 | 命令行参数 | 说明 |
|-------|---------|-----------|------|
| 钱包地址 | WALLET_ADDRESS | -w, --wallet | 你的EVM钱包地址 |
| 私钥 | PRIVATE_KEY | -k, --key | 你的钱包私钥 |
| RPC地址 | MONAD_RPC | -r, --rpc | Monad测试网RPC地址 |
| 合约地址 | CONTRACT_ADDRESS | -c, --contract | 需要交互的合约地址 |
| 合约方法 | CONTRACT_METHOD | -m, --method | 合约交互方法 |
| 链ID | CHAIN_ID | -i, --chainid | 链ID，默认为Monad测试网的10143 |
| 详细日志 | - | -v, --verbose | 是否显示详细日志 |

## 日志输出

脚本会输出详细的执行日志，包括：

- 基本操作日志（INFO级别）
- 详细调试信息（DEBUG级别，需要使用-v参数开启）
- 错误信息（ERROR级别）
- 重试信息（WARN级别）

## 错误处理和重试

脚本内置了重试机制，对于网络请求会自动重试最多3次，每次重试间隔时间会递增，提高成功率。

## 注意事项

- 请妥善保管你的私钥，不要将包含私钥的文件上传到公开仓库
- 建议将私钥存储在环境变量或.env文件中，而不是直接硬编码在脚本中
- 脚本执行过程中可能需要等待区块确认，请耐心等待
- 确保你的钱包中有足够的MONAD代币支付交易gas费

## 自动化运行

你可以使用系统的定时任务来设置脚本的定时运行，实现每日自动签到：

### Windows计划任务

1. 打开任务计划程序
2. 创建基本任务
3. 设置每日触发
4. 设置操作为启动程序
5. 程序路径设置为python.exe，参数设置为脚本路径

### Linux Cron任务

```bash
# 每天早上8点运行签到脚本
0 8 * * * cd /path/to/script && python apriori_checkin.py >> checkin.log 2>&1
```

## 问题排查

如果遇到问题，请尝试以下步骤：

1. 使用`-v`参数运行脚本，查看详细日志
2. 检查网络连接是否正常
3. 确认私钥和钱包地址是否正确
4. 检查钱包中是否有足够的MONAD代币支付gas费


#### SSL连接错误

如果遇到类似以下错误：

```
问题1
[2025-08-08 21:40:12] [ERROR] 登录请求时发生网络错误: HTTPSConnectionPool(host='wallet-collection-api.apr.io', port=443): Max retries exceeded with url: /auth/login (Caused by SSLError(SSLEOFError(8, '[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1010)')))```

可能的原因：
- 网络连接不稳定
- SSL证书问题
- 代理或防火墙拦截

解决方法：
1. 检查网络连接是否稳定
2. 尝试使用VPN或更换网络环境
3. 检查系统时间是否正确（SSL验证可能受系统时间影响）


### 调试模式

脚本现在包含增强的调试功能，使用`-v`参数运行时会输出：

- 请求URL和参数
- 请求头信息
- 响应状态码
- 响应头信息
- 响应内容
- 详细的错误信息

这些信息对于排查API相关问题非常有帮助。


问题2
错误响应内容: f"message":"You can only check in with your primary wallet or related wallets" "error":"forbiden","statuscode":403}
请注意你钱包地址的大小写