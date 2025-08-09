import requests
import json
import time
import os
import sys
import argparse
import random
from datetime import datetime, timedelta, UTC
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from dotenv import load_dotenv
from retry import retry
import concurrent.futures
import csv

# 加载环境变量
load_dotenv()

# 尝试加载JSON配置文件
def load_config_from_json(config_file="multi_wallet_config.json"):
    """从JSON文件加载配置"""
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                return config
        except Exception as e:
            print(f"加载配置文件失败: {str(e)}")
    return {}

# 日志输出函数
def log(message, level="INFO", wallet_address=None):
    """日志输出函数"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    wallet_info = f"[{wallet_address[:8]}...]" if wallet_address else ""
    print(f"[{timestamp}] [{level}] {wallet_info} {message}")
    
def debug(message, wallet_address=None, verbose=False):
    """调试日志，仅在VERBOSE模式下显示"""
    if verbose:
        log(message, "DEBUG", wallet_address)

# 通用请求头
def get_headers():
    return {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "content-type": "application/json",
        "priority": "u=1, i",
        "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Microsoft Edge\";v=\"138\"",
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": "\"Android\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "Referer": "https://of.apr.io/"
    }

@retry(max_tries=3, delay_seconds=2, exceptions=(requests.RequestException, json.JSONDecodeError))
def get_nonce(wallet_address, proxy=None, verbose=False):
    """获取nonce"""
    url = f"https://wallet-collection-api.apr.io/auth/nonce/{wallet_address}"
    headers = get_headers()
    debug(f"请求URL: {url}", wallet_address, verbose)
    debug(f"请求头: {json.dumps({k: v for k, v in headers.items() if k.lower() not in ['authorization']}, indent=2)}", wallet_address, verbose)
    debug(f"使用代理: {proxy}", wallet_address, verbose) if proxy else None
    
    try:
        response = requests.get(url, headers=headers, timeout=10, proxies={"http": proxy, "https": proxy} if proxy else None)
        
        # 打印响应状态和内容，即使状态码不是200
        debug(f"响应状态码: {response.status_code}", wallet_address, verbose)
        debug(f"响应头: {json.dumps(dict(response.headers), indent=2)}", wallet_address, verbose)
        
        try:
            debug(f"响应内容: {json.dumps(response.json(), indent=2)}", wallet_address, verbose)
        except:
            debug(f"响应内容(非JSON): {response.text}", wallet_address, verbose)
        
        response.raise_for_status()  # 抛出HTTP错误
        
        data = response.json()
        return data["nonce"], data["message"]
    except requests.RequestException as e:
        log(f"请求nonce时发生网络错误: {str(e)}", "ERROR", wallet_address)
        if hasattr(e, 'response') and e.response is not None:
            log(f"错误响应状态码: {e.response.status_code}", "ERROR", wallet_address)
            try:
                log(f"错误响应内容: {e.response.text}", "ERROR", wallet_address)
            except:
                log("无法获取错误响应内容", "ERROR", wallet_address)
        raise
    except json.JSONDecodeError as e:
        log(f"解析nonce响应JSON失败: {str(e)}", "ERROR", wallet_address)
        raise
    except KeyError as e:
        log(f"nonce响应缺少必要字段: {str(e)}", "ERROR", wallet_address)
        log(f"响应内容: {response.text}", "ERROR", wallet_address)
        raise Exception(f"获取nonce失败: 响应格式不正确")

def sign_message(message, private_key):
    """使用私钥对消息进行签名"""
    account = Account.from_key(private_key)
    message_hash = encode_defunct(text=message)
    signed_message = account.sign_message(message_hash)
    return signed_message.signature.hex()

@retry(max_tries=3, delay_seconds=2, exceptions=(requests.RequestException, json.JSONDecodeError))
def login(wallet_address, signature, message, proxy=None, verbose=False):
    """使用签名登录"""
    url = "https://wallet-collection-api.apr.io/auth/login"
    headers = get_headers()
    payload = {
        "walletAddress": wallet_address,
        "signature": f"0x{signature}",
        "message": message
    }
    
    debug(f"请求URL: {url}", wallet_address, verbose)
    debug(f"请求参数: {json.dumps({**payload, 'signature': signature[:10] + '...'}, indent=2)}", wallet_address, verbose)
    debug(f"请求头: {json.dumps({k: v for k, v in headers.items() if k.lower() not in ['authorization']}, indent=2)}", wallet_address, verbose)
    debug(f"使用代理: {proxy}", wallet_address, verbose) if proxy else None
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10, proxies={"http": proxy, "https": proxy} if proxy else None)
        
        # 打印响应状态和内容，即使状态码不是200
        debug(f"响应状态码: {response.status_code}", wallet_address, verbose)
        debug(f"响应头: {json.dumps(dict(response.headers), indent=2)}", wallet_address, verbose)
        
        try:
            debug(f"响应内容: {json.dumps(response.json(), indent=2)}", wallet_address, verbose)
        except:
            debug(f"响应内容(非JSON): {response.text}", wallet_address, verbose)
        
        response.raise_for_status()  # 抛出HTTP错误
        
        data = response.json()
        return data["access_token"], data["user"]
    except requests.RequestException as e:
        log(f"登录请求时发生网络错误: {str(e)}", "ERROR", wallet_address)
        if hasattr(e, 'response') and e.response is not None:
            log(f"错误响应状态码: {e.response.status_code}", "ERROR", wallet_address)
            try:
                log(f"错误响应内容: {e.response.text}", "ERROR", wallet_address)
            except:
                log("无法获取错误响应内容", "ERROR", wallet_address)
        raise
    except json.JSONDecodeError as e:
        log(f"解析登录响应JSON失败: {str(e)}", "ERROR", wallet_address)
        raise
    except KeyError as e:
        log(f"登录响应缺少必要字段: {str(e)}", "ERROR", wallet_address)
        log(f"响应内容: {response.text}", "ERROR", wallet_address)
        raise Exception(f"登录失败: 响应格式不正确")

def interact_with_contract(wallet_address, private_key, monad_rpc, contract_address, contract_method, chain_id, verbose=False):
    """与Monad合约交互"""
    # 连接到Monad测试网
    log(f"连接到Monad测试网: {monad_rpc}", wallet_address=wallet_address)
    w3 = Web3(Web3.HTTPProvider(monad_rpc))
    
    # 检查连接
    if not w3.is_connected():
        raise Exception("无法连接到Monad测试网")
    log("成功连接到Monad测试网", wallet_address=wallet_address)
    
    # 创建交易
    account = Account.from_key(private_key)
    debug(f"使用账户地址: {account.address}", wallet_address, verbose)
    
    # 获取nonce
    nonce = w3.eth.get_transaction_count(account.address)
    debug(f"获取到账户nonce: {nonce}", wallet_address, verbose)
    
    # 获取当前gas价格
    gas_price = w3.eth.gas_price
    debug(f"当前gas价格: {gas_price}", wallet_address, verbose)
    
    # 构建交易
    tx = {
        'from': account.address,
        'to': Web3.to_checksum_address(contract_address),
        'value': 0,  # 不发送ETH
        'gas': 100000,  # 设置适当的gas限制
        'gasPrice': gas_price,
        'nonce': nonce,
        'data': contract_method,  # 合约方法
        'chainId': chain_id
    }
    debug(f"交易详情: {json.dumps(tx, default=str)}", wallet_address, verbose)
    
    # 签名交易
    log("签名交易...", wallet_address=wallet_address)
    signed_tx = w3.eth.account.sign_transaction(tx, private_key)
    
    # 发送交易
    log("发送交易到网络...", wallet_address=wallet_address)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_hash_hex = tx_hash.hex()
    log(f"交易已发送，等待确认: {tx_hash_hex}", wallet_address=wallet_address)
    
    # 等待交易确认
    log("等待交易确认...", wallet_address=wallet_address)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    debug(f"交易收据: {json.dumps(dict(receipt), default=str)}", wallet_address, verbose)
    
    # 检查交易状态
    if receipt.status == 1:
        log("交易已成功确认", wallet_address=wallet_address)
        return tx_hash_hex
    else:
        raise Exception(f"交易失败，状态码: {receipt.status}")

@retry(max_tries=3, delay_seconds=2, exceptions=(requests.RequestException, json.JSONDecodeError))
def checkin(access_token, wallet_address, transaction_hash, chain_id, proxy=None, verbose=False):
    """签到"""
    url = "https://wallet-collection-api.apr.io/wallets/checkin"
    
    # 更新请求头，添加授权信息
    headers = get_headers()
    headers["authorization"] = f"Bearer {access_token}"
    
    payload = {
        "walletAddress": wallet_address,
        "transactionHash": f"0x{transaction_hash}",
        "chainId": chain_id
    }
    
    debug(f"请求URL: {url}", wallet_address, verbose)
    debug(f"请求参数: {json.dumps(payload, indent=2)}", wallet_address, verbose)
    debug(f"请求头: {json.dumps({k: v for k, v in headers.items() if k.lower() not in ['authorization']}, indent=2)}", wallet_address, verbose)
    debug(f"授权头: Bearer {access_token[:15]}...", wallet_address, verbose)
    debug(f"使用代理: {proxy}", wallet_address, verbose) if proxy else None
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10, proxies={"http": proxy, "https": proxy} if proxy else None)
        
        # 打印响应状态和内容，即使状态码不是200
        debug(f"响应状态码: {response.status_code}", wallet_address, verbose)
        debug(f"响应头: {json.dumps(dict(response.headers), indent=2)}", wallet_address, verbose)
        
        try:
            debug(f"响应内容: {json.dumps(response.json(), indent=2)}", wallet_address, verbose)
        except:
            debug(f"响应内容(非JSON): {response.text}", wallet_address, verbose)
        
        response.raise_for_status()  # 抛出HTTP错误
        
        data = response.json()
        return data
    except requests.RequestException as e:
        log(f"签到请求时发生网络错误: {str(e)}", "ERROR", wallet_address)
        if hasattr(e, 'response') and e.response is not None:
            log(f"错误响应状态码: {e.response.status_code}", "ERROR", wallet_address)
            try:
                log(f"错误响应内容: {e.response.text}", "ERROR", wallet_address)
            except:
                log("无法获取错误响应内容", "ERROR", wallet_address)
        raise
    except json.JSONDecodeError as e:
        log(f"解析签到响应JSON失败: {str(e)}", "ERROR", wallet_address)
        raise
    except KeyError as e:
        log(f"签到响应缺少必要字段: {str(e)}", "ERROR", wallet_address)
        log(f"响应内容: {response.text}", "ERROR", wallet_address)
        raise Exception(f"签到失败: 响应格式不正确")

def process_wallet(wallet_config, global_config):
    """处理单个钱包的签到流程"""
    wallet_address = wallet_config.get("address")
    private_key = wallet_config.get("private_key")
    proxy = wallet_config.get("proxy")
    verbose = wallet_config.get("verbose", global_config.get("verbose", False))
    monad_rpc = wallet_config.get("monad_rpc", global_config.get("monad_rpc"))
    contract_address = wallet_config.get("contract_address", global_config.get("contract_address"))
    contract_method = wallet_config.get("contract_method", global_config.get("contract_method"))
    chain_id = wallet_config.get("chain_id", global_config.get("chain_id"))
    
    try:
        # 检查私钥是否设置
        if not private_key:
            raise ValueError(f"钱包 {wallet_address} 未设置私钥！")
        
        # 打印当前配置信息
        debug("当前运行配置:", wallet_address, verbose)
        debug(f"  钱包地址: {wallet_address}", wallet_address, verbose)
        debug(f"  Monad RPC: {monad_rpc}", wallet_address, verbose)
        debug(f"  合约地址: {contract_address}", wallet_address, verbose)
        debug(f"  合约方法: {contract_method}", wallet_address, verbose)
        debug(f"  链ID: {chain_id}", wallet_address, verbose)
        debug(f"  代理: {proxy}", wallet_address, verbose)
        debug(f"  详细日志: {'启用' if verbose else '禁用'}", wallet_address, verbose)
            
        # 1. 获取nonce
        log("开始获取nonce...", wallet_address=wallet_address)
        try:
            nonce, nonce_message = get_nonce(wallet_address, proxy, verbose)
            log(f"获取到nonce: {nonce}", wallet_address=wallet_address)
            debug(f"完整nonce消息: {nonce_message}", wallet_address, verbose)
        except Exception as e:
            log(f"获取nonce失败: {str(e)}", "ERROR", wallet_address)
            raise
        
        # 2. 创建签名消息
        log("创建签名消息...", wallet_address=wallet_address)
        try:
            message = nonce_message
            log("签名消息创建成功", wallet_address=wallet_address)
            debug(f"签名消息内容: {message}", wallet_address, verbose)
        except Exception as e:
            log(f"创建签名消息失败: {str(e)}", "ERROR", wallet_address)
            raise
        
        # 3. 签名消息
        log("对消息进行签名...", wallet_address=wallet_address)
        try:
            signature = sign_message(message, private_key)
            log(f"签名成功: {signature[:10]}...{signature[-10:]}", wallet_address=wallet_address)
        except Exception as e:
            log(f"签名消息失败: {str(e)}", "ERROR", wallet_address)
            raise
        
        # 4. 登录
        log("使用签名登录...", wallet_address=wallet_address)
        try:
            access_token, user = login(wallet_address, signature, message, proxy, verbose)
            log(f"登录成功，用户ID: {user['id']}", wallet_address=wallet_address)
            debug(f"获取到的access_token: {access_token[:15]}...", wallet_address, verbose)
        except Exception as e:
            log(f"登录失败: {str(e)}", "ERROR", wallet_address)
            raise
        
        # 5. 与合约交互
        log("开始与Monad合约交互...", wallet_address=wallet_address)
        try:
            tx_hash = interact_with_contract(wallet_address, private_key, monad_rpc, contract_address, contract_method, chain_id, verbose)
            log(f"合约交互成功，交易哈希: {tx_hash}", wallet_address=wallet_address)
        except Exception as e:
            log(f"合约交互失败: {str(e)}", "ERROR", wallet_address)
            raise
        
        # 6. 签到
        log("提交签到请求...", wallet_address=wallet_address)
        try:
            result = checkin(access_token, wallet_address, tx_hash, chain_id, proxy, verbose)
            log(f"签到成功: {result['message']}", wallet_address=wallet_address)
            log(f"当前签到次数: {result['checkintimes']}", wallet_address=wallet_address)
            return {
                "wallet_address": wallet_address,
                "status": "success",
                "message": result['message'],
                "checkintimes": result['checkintimes']
            }
        except Exception as e:
            log(f"签到失败: {str(e)}", "ERROR", wallet_address)
            raise
        
    except Exception as e:
        log(f"处理钱包 {wallet_address} 时发生错误: {str(e)}", "ERROR", wallet_address)
        debug(f"错误详情: {repr(e)}", wallet_address, verbose)
        return {
            "wallet_address": wallet_address,
            "status": "failed",
            "error": str(e)
        }

def load_wallets_from_csv(csv_file):
    """从CSV文件加载钱包信息"""
    wallets = []
    if os.path.exists(csv_file):
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    wallet = {
                        "address": row.get("address", "").strip(),
                        "private_key": row.get("private_key", "").strip(),
                        "proxy": row.get("proxy", "").strip() or None
                    }
                    # 只添加有效的钱包配置
                    if wallet["address"] and wallet["private_key"]:
                        wallets.append(wallet)
        except Exception as e:
            log(f"从CSV加载钱包失败: {str(e)}", "ERROR")
    return wallets

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="Apriori多钱包自动签到脚本")
    parser.add_argument("-c", "--config", default="multi_wallet_config.json", help="配置文件路径")
    parser.add_argument("--csv", help="CSV钱包文件路径")
    parser.add_argument("-r", "--rpc", help="Monad RPC地址")
    parser.add_argument("--contract", help="合约地址")
    parser.add_argument("--method", help="合约方法")
    parser.add_argument("--chainid", type=int, help="链ID")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细日志")
    parser.add_argument("-t", "--threads", type=int, default=3, help="并发处理的线程数")
    parser.add_argument("--delay", type=int, default=5, help="每个钱包处理之间的延迟(秒)")
    
    args = parser.parse_args()
    
    # 加载配置
    config = load_config_from_json(args.config)
    
    # 全局配置
    global_config = {
        "monad_rpc": args.rpc or config.get("network", {}).get("monad_rpc", "https://rpc.ankr.com/monad_testnet"),
        "contract_address": args.contract or config.get("contract", {}).get("address", "0x703e753e9a2aca1194ded65833eaec17dcfeac1b"),
        "contract_method": args.method or config.get("contract", {}).get("method", "0x183ff085"),
        "chain_id": args.chainid or config.get("network", {}).get("chain_id", 10143),
        "verbose": args.verbose or config.get("settings", {}).get("verbose", False),
        "threads": args.threads or config.get("settings", {}).get("threads", 3),
        "delay": args.delay or config.get("settings", {}).get("delay", 5)
    }
    
    # 获取钱包列表
    wallets = []
    
    # 从CSV加载钱包
    if args.csv:
        csv_wallets = load_wallets_from_csv(args.csv)
        log(f"从CSV文件加载了 {len(csv_wallets)} 个钱包")
        wallets.extend(csv_wallets)
    
    # 从配置文件加载钱包
    config_wallets = config.get("wallets", [])
    if config_wallets:
        log(f"从配置文件加载了 {len(config_wallets)} 个钱包")
        wallets.extend(config_wallets)
    
    if not wallets:
        log("没有找到任何钱包配置，请检查配置文件或CSV文件", "ERROR")
        return False
    
    log(f"共加载 {len(wallets)} 个钱包配置")
    log(f"将使用 {global_config['threads']} 个线程并发处理")
    log(f"每个钱包处理之间将延迟 {global_config['delay']} 秒")
    
    # 处理结果
    results = []
    
    # 使用线程池处理多个钱包
    with concurrent.futures.ThreadPoolExecutor(max_workers=global_config["threads"]) as executor:
        # 提交所有任务
        future_to_wallet = {}
        for wallet in wallets:
            # 提交任务
            future = executor.submit(process_wallet, wallet, global_config)
            future_to_wallet[future] = wallet
            # 添加延迟，避免请求过于集中
            time.sleep(global_config["delay"])
        
        # 获取结果
        for future in concurrent.futures.as_completed(future_to_wallet):
            wallet = future_to_wallet[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                log(f"处理钱包 {wallet.get('address')} 时发生异常: {str(e)}", "ERROR")
                results.append({
                    "wallet_address": wallet.get("address"),
                    "status": "failed",
                    "error": str(e)
                })
    
    # 统计结果
    success_count = sum(1 for r in results if r.get("status") == "success")
    failed_count = sum(1 for r in results if r.get("status") == "failed")
    
    log(f"签到完成，成功: {success_count}，失败: {failed_count}")
    
    # 保存结果到文件
    result_file = f"checkin_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total": len(results),
            "success": success_count,
            "failed": failed_count,
            "results": results
        }, f, indent=2, ensure_ascii=False)
    
    log(f"结果已保存到 {result_file}")
    
    return success_count > 0

if __name__ == "__main__":
    # 运行主程序
    success = main()
    
    # 设置退出码
    sys.exit(0 if success else 1)