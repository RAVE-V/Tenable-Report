import time
import functools
import logging
from typing import Callable, Any

logger = logging.getLogger(__name__)

def measure_performance(func: Callable) -> Callable:
    """Decorator to measure and log function execution time"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        duration = end_time - start_time
        logger.info(f"Performance: {func.__qualname__} took {duration:.4f} seconds")
        return result
    return wrapper
