package com.zigaai.exception;

/**
 * 业务异常
 */
public class BizException extends RuntimeException {

    public BizException(String message) {
        super(message);
    }

    /**
     * 避免对api异常进行昂贵且无用的堆栈跟踪
     */
    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }

}
