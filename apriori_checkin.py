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

# 加载环境变量
load_dotenv()

# 尝试加载JSON配置文件
def load_config_from_json(config_file="config.json"):
    """从JSON文件加载配置"""
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                return {
                    "wallet_address": config.get("wallet", {}).get("address"),
                    "private_key": config.get("wallet", {}).get("private_key"),
                    "monad_rpc": config.get("network", {}).get("monad_rpc"),
                    "chain_id": config.get("network", {}).get("chain_id"),
                    "contract_address": config.get("contract", {}).get("address"),
                    "contract_method": config.get("contract", {}).get("method"),
                    "verbose": config.get("settings", {}).get("verbose", False)
                }
        except Exception as e:
            print(f"加载配置文件失败: {str(e)}")
    return {}

# 尝试加载配置文件
config = load_config_from_json()

# 配置信息 (优先级: 命令行参数 > 环境变量 > 配置文件 > 默认值)
WALLET_ADDRESS = os.getenv("WALLET_ADDRESS", config.get("wallet_address", "0x341faa54047D3371976e377885a604542012fCC7"))  # 钱包地址
PRIVATE_KEY = os.getenv("PRIVATE_KEY", config.get("private_key", ""))  # 从环境变量获取私钥
MONAD_RPC = os.getenv("MONAD_RPC", config.get("monad_rpc", "https://rpc.ankr.com/monad_testnet"))
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", config.get("contract_address", "0x703e753e9a2aca1194ded65833eaec17dcfeac1b"))
CONTRACT_METHOD = os.getenv("CONTRACT_METHOD", config.get("contract_method", "0x183ff085"))
CHAIN_ID = int(os.getenv("CHAIN_ID", str(config.get("chain_id", 10143))))  # Monad测试网链ID
VERBOSE = config.get("verbose", False)  # 默认不显示详细日志

# 是否显示详细日志
VERBOSE = False

def log(message, level="INFO"):
    """日志输出函数"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")
    
def debug(message):
    """调试日志，仅在VERBOSE模式下显示"""
    if VERBOSE:
        log(message, "DEBUG")

# 通用请求头
HEADERS = {
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
def get_nonce():
    """获取nonce"""
    url = f"https://wallet-collection-api.apr.io/auth/nonce/{WALLET_ADDRESS}"
    debug(f"请求URL: {url}")
    debug(f"请求头: {json.dumps({k: v for k, v in HEADERS.items() if k.lower() not in ['authorization']}, indent=2)}")
    
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        
        # 打印响应状态和内容，即使状态码不是200
        debug(f"响应状态码: {response.status_code}")
        debug(f"响应头: {json.dumps(dict(response.headers), indent=2)}")
        
        try:
            debug(f"响应内容: {json.dumps(response.json(), indent=2)}")
        except:
            debug(f"响应内容(非JSON): {response.text}")
        
        response.raise_for_status()  # 抛出HTTP错误
        
        data = response.json()
        return data["nonce"], data["message"]
    except requests.RequestException as e:
        log(f"请求nonce时发生网络错误: {str(e)}", "ERROR")
        if hasattr(e, 'response') and e.response is not None:
            log(f"错误响应状态码: {e.response.status_code}", "ERROR")
            try:
                log(f"错误响应内容: {e.response.text}", "ERROR")
            except:
                log("无法获取错误响应内容", "ERROR")
        raise
    except json.JSONDecodeError as e:
        log(f"解析nonce响应JSON失败: {str(e)}", "ERROR")
        raise
    except KeyError as e:
        log(f"nonce响应缺少必要字段: {str(e)}", "ERROR")
        log(f"响应内容: {response.text}", "ERROR")
        raise Exception(f"获取nonce失败: 响应格式不正确")


def sign_message(message):
    """使用私钥对消息进行签名"""
    account = Account.from_key(PRIVATE_KEY)
    message_hash = encode_defunct(text=message)
    signed_message = account.sign_message(message_hash)
    return signed_message.signature.hex()

@retry(max_tries=3, delay_seconds=2, exceptions=(requests.RequestException, json.JSONDecodeError))
def login(wallet_address, signature, message):
    """使用签名登录"""
    url = "https://wallet-collection-api.apr.io/auth/login"
    payload = {
        "walletAddress": wallet_address,
        "signature": f"0x{signature}",
        "message": message
    }
    
    debug(f"请求URL: {url}")
    debug(f"请求参数: {json.dumps({**payload, 'signature': signature[:10] + '...'}, indent=2)}")
    debug(f"请求头: {json.dumps({k: v for k, v in HEADERS.items() if k.lower() not in ['authorization']}, indent=2)}")
    
    try:
        response = requests.post(url, headers=HEADERS, json=payload, timeout=10)
        
        # 打印响应状态和内容，即使状态码不是200
        debug(f"响应状态码: {response.status_code}")
        debug(f"响应头: {json.dumps(dict(response.headers), indent=2)}")
        
        try:
            debug(f"响应内容: {json.dumps(response.json(), indent=2)}")
        except:
            debug(f"响应内容(非JSON): {response.text}")
        
        response.raise_for_status()  # 抛出HTTP错误
        
        data = response.json()
        return data["access_token"], data["user"]
    except requests.RequestException as e:
        log(f"登录请求时发生网络错误: {str(e)}", "ERROR")
        if hasattr(e, 'response') and e.response is not None:
            log(f"错误响应状态码: {e.response.status_code}", "ERROR")
            try:
                log(f"错误响应内容: {e.response.text}", "ERROR")
            except:
                log("无法获取错误响应内容", "ERROR")
        raise
    except json.JSONDecodeError as e:
        log(f"解析登录响应JSON失败: {str(e)}", "ERROR")
        raise
    except KeyError as e:
        log(f"登录响应缺少必要字段: {str(e)}", "ERROR")
        log(f"响应内容: {response.text}", "ERROR")
        raise Exception(f"登录失败: 响应格式不正确")

def interact_with_contract():
    """与Monad合约交互"""
    # 连接到Monad测试网
    log(f"连接到Monad测试网: {MONAD_RPC}")
    w3 = Web3(Web3.HTTPProvider(MONAD_RPC))
    
    # 检查连接
    if not w3.is_connected():
        raise Exception("无法连接到Monad测试网")
    log("成功连接到Monad测试网")
    
    # 创建交易
    account = Account.from_key(PRIVATE_KEY)
    debug(f"使用账户地址: {account.address}")
    
    # 获取nonce
    nonce = w3.eth.get_transaction_count(account.address)
    debug(f"获取到账户nonce: {nonce}")
    
    # 获取当前gas价格
    gas_price = w3.eth.gas_price
    debug(f"当前gas价格: {gas_price}")
    
    # 构建交易
    tx = {
        'from': account.address,
        'to': Web3.to_checksum_address(CONTRACT_ADDRESS),
        'value': 0,  # 不发送ETH
        'gas': 100000,  # 设置适当的gas限制
        'gasPrice': gas_price,
        'nonce': nonce,
        'data': CONTRACT_METHOD,  # 合约方法
        'chainId': CHAIN_ID
    }
    debug(f"交易详情: {json.dumps(tx, default=str)}")
    
    # 签名交易
    log("签名交易...")
    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    
    # 发送交易
    log("发送交易到网络...")
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_hash_hex = tx_hash.hex()
    log(f"交易已发送，等待确认: {tx_hash_hex}")
    
    # 等待交易确认
    log("等待交易确认...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    debug(f"交易收据: {json.dumps(dict(receipt), default=str)}")
    
    # 检查交易状态
    if receipt.status == 1:
        log("交易已成功确认")
        return tx_hash_hex
    else:
        raise Exception(f"交易失败，状态码: {receipt.status}")

@retry(max_tries=3, delay_seconds=2, exceptions=(requests.RequestException, json.JSONDecodeError))
def checkin(access_token, wallet_address, transaction_hash):
    """签到"""
    url = "https://wallet-collection-api.apr.io/wallets/checkin"
    
    # 更新请求头，添加授权信息
    headers = HEADERS.copy()
    headers["authorization"] = f"Bearer {access_token}"
    
    payload = {
        "walletAddress": wallet_address,
        "transactionHash": f"0x{transaction_hash}",
        "chainId": CHAIN_ID
    }
    
    debug(f"请求URL: {url}")
    debug(f"请求参数: {json.dumps(payload, indent=2)}")
    debug(f"请求头: {json.dumps({k: v for k, v in headers.items() if k.lower() not in ['authorization']}, indent=2)}")
    debug(f"授权头: Bearer {access_token[:15]}...")
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        
        # 打印响应状态和内容，即使状态码不是200
        debug(f"响应状态码: {response.status_code}")
        debug(f"响应头: {json.dumps(dict(response.headers), indent=2)}")
        
        try:
            debug(f"响应内容: {json.dumps(response.json(), indent=2)}")
        except:
            debug(f"响应内容(非JSON): {response.text}")
        
        response.raise_for_status()  # 抛出HTTP错误
        
        data = response.json()
        return data
    except requests.RequestException as e:
        log(f"签到请求时发生网络错误: {str(e)}", "ERROR")
        if hasattr(e, 'response') and e.response is not None:
            log(f"错误响应状态码: {e.response.status_code}", "ERROR")
            try:
                log(f"错误响应内容: {e.response.text}", "ERROR")
            except:
                log("无法获取错误响应内容", "ERROR")
        raise
    except json.JSONDecodeError as e:
        log(f"解析签到响应JSON失败: {str(e)}", "ERROR")
        raise
    except KeyError as e:
        log(f"签到响应缺少必要字段: {str(e)}", "ERROR")
        log(f"响应内容: {response.text}", "ERROR")
        raise Exception(f"签到失败: 响应格式不正确")

def main():
    try:
        # 检查私钥是否设置
        if not PRIVATE_KEY:
            raise ValueError("请设置私钥！可以在.env文件中设置PRIVATE_KEY环境变量")
        
        # 打印当前配置信息
        debug("当前运行配置:")
        debug(f"  钱包地址: {WALLET_ADDRESS}")
        debug(f"  Monad RPC: {MONAD_RPC}")
        debug(f"  合约地址: {CONTRACT_ADDRESS}")
        debug(f"  合约方法: {CONTRACT_METHOD}")
        debug(f"  链ID: {CHAIN_ID}")
        debug(f"  详细日志: {'启用' if VERBOSE else '禁用'}")
            
        # 1. 获取nonce
        log("开始获取nonce...")
        try:
            nonce, nonce_message = get_nonce()
            log(f"获取到nonce: {nonce}")
            debug(f"完整nonce消息: {nonce_message}")
        except Exception as e:
            log(f"获取nonce失败: {str(e)}", "ERROR")
            raise
        
        # 2. 创建签名消息
        log("创建签名消息...")
        try:
            message = nonce_message
            log("签名消息创建成功")
            debug(f"签名消息内容: {message}")
        except Exception as e:
            log(f"创建签名消息失败: {str(e)}", "ERROR")
            raise
        
        # 3. 签名消息
        log("对消息进行签名...")
        try:
            signature = sign_message(message)
            log(f"签名成功: {signature[:10]}...{signature[-10:]}")
        except Exception as e:
            log(f"签名消息失败: {str(e)}", "ERROR")
            raise
        
        # 4. 登录
        log("使用签名登录...")
        try:
            access_token, user = login(WALLET_ADDRESS, signature, message)
            log(f"登录成功，用户ID: {user['id']}")
            debug(f"获取到的access_token: {access_token[:15]}...")
        except Exception as e:
            log(f"登录失败: {str(e)}", "ERROR")
            raise
        
        # 5. 与合约交互
        log("开始与Monad合约交互...")
        try:
            tx_hash = interact_with_contract()
            log(f"合约交互成功，交易哈希: {tx_hash}")
        except Exception as e:
            log(f"合约交互失败: {str(e)}", "ERROR")
            raise
        
        # 6. 签到
        log("提交签到请求...")
        try:
            result = checkin(access_token, WALLET_ADDRESS, tx_hash)
            log(f"签到成功: {result['message']}")
            log(f"当前签到次数: {result['checkintimes']}")
        except Exception as e:
            log(f"签到失败: {str(e)}", "ERROR")
            raise
        
        return True
    except Exception as e:
        log(f"发生错误: {str(e)}", "ERROR")
        debug(f"错误详情: {repr(e)}")
        return False

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="Apriori自动签到脚本")
    parser.add_argument("-w", "--wallet", help="钱包地址")
    parser.add_argument("-k", "--key", help="钱包私钥")
    parser.add_argument("-r", "--rpc", help="Monad RPC地址")
    parser.add_argument("-c", "--contract", help="合约地址")
    parser.add_argument("-m", "--method", help="合约方法")
    parser.add_argument("-i", "--chainid", type=int, help="链ID")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细日志")
    
    return parser.parse_args()

def update_config_from_args(args):
    """从命令行参数更新配置"""
    global WALLET_ADDRESS, PRIVATE_KEY, MONAD_RPC, CONTRACT_ADDRESS, CONTRACT_METHOD, CHAIN_ID, VERBOSE
    
    if args.wallet:
        WALLET_ADDRESS = args.wallet
    if args.key:
        PRIVATE_KEY = args.key
    if args.rpc:
        MONAD_RPC = args.rpc
    if args.contract:
        CONTRACT_ADDRESS = args.contract
    if args.method:
        CONTRACT_METHOD = args.method
    if args.chainid:
        CHAIN_ID = args.chainid
    if args.verbose:
        VERBOSE = True
        
    # 打印当前配置
    if VERBOSE:
        debug(f"当前配置:")
        debug(f"  钱包地址: {WALLET_ADDRESS}")
        debug(f"  Monad RPC: {MONAD_RPC}")
        debug(f"  合约地址: {CONTRACT_ADDRESS}")
        debug(f"  合约方法: {CONTRACT_METHOD}")
        debug(f"  链ID: {CHAIN_ID}")

if __name__ == "__main__":
    # 解析命令行参数
    args = parse_args()
    
    # 更新配置
    update_config_from_args(args)
    
    # 运行主程序
    success = main()
    
    # 设置退出码
    sys.exit(0 if success else 1)