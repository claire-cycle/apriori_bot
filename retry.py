import time
import random
import datetime
from functools import wraps

# 日志函数，与主脚本保持一致
def log_retry(message, level="INFO"):
    """日志输出函数"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def retry(max_tries=3, delay_seconds=1, backoff=2, exceptions=(Exception,)):
    """
    重试装饰器
    
    参数:
        max_tries: 最大尝试次数
        delay_seconds: 初始延迟秒数
        backoff: 延迟增长因子
        exceptions: 需要重试的异常类型
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            mtries, mdelay = max_tries, delay_seconds
            last_exception = None
            
            while mtries > 0:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    mtries -= 1
                    if mtries == 0:
                        raise
                    
                    # 添加随机抖动，避免多个请求同时发送
                    sleep_time = mdelay + random.uniform(0, 0.5)
                    log_retry(f"重试 {func.__name__}，第{max_tries - mtries}/{max_tries - 1}次，等待{sleep_time:.2f}秒...", "WARN")
                    log_retry(f"错误信息: {str(e)}", "WARN")
                    time.sleep(sleep_time)
                    mdelay *= backoff
            return None

        return wrapper
    return decorator