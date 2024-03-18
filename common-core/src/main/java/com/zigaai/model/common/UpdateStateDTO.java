package com.zigaai.model.common;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;

@Getter
@Setter
@ToString
public class UpdateStateDTO implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 状态
     */
    private Byte state;

    /**
     * id列表
     */
    private List<Long> ids;

}
