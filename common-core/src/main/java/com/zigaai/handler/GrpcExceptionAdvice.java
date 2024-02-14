package com.zigaai.handler;

import com.zigaai.exception.BizException;
import com.zigaai.exception.BizIllegalArgumentException;
import io.grpc.Status;
import net.devh.boot.grpc.server.advice.GrpcAdvice;
import net.devh.boot.grpc.server.advice.GrpcExceptionHandler;

@GrpcAdvice
public class GrpcExceptionAdvice {

    @GrpcExceptionHandler
    public Status handleBizException(BizException e) {
        return Status.UNKNOWN.withDescription(e.getMessage()).withCause(e);
    }

    @GrpcExceptionHandler
    public Status handleBizIllegalArgumentException(BizIllegalArgumentException e) {
        return Status.INVALID_ARGUMENT.withDescription(e.getMessage()).withCause(e);
    }

}
