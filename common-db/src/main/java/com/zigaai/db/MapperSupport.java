package com.zigaai.db;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.toolkit.Constants;
import org.apache.ibatis.annotations.Param;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

/**
 * 使用xml复写mp
 *
 * @param <T> 实体
 */
public interface MapperSupport<T> extends BaseMapper<T> {

    @Override
    default T selectById(@Param("id") Serializable id) {
        return this.getById(id);
    }

    @Override
    default List<T> selectBatchIds(@Param("ids") Collection<? extends Serializable> ids) {
        return this.listByIds(ids);
    }

    @Override
    int insert(T entity);

    @Override
    int updateById(@Param(Constants.ENTITY) T entity);

    @Override
    int deleteById(@Param("id") Serializable id);

    T getById(@Param("id") Serializable id, @Param("columns") String... columns);

    List<T> listByIds(@Param("ids") Collection<? extends Serializable> ids, @Param("columns") String... columns);

    int insertBatch(@Param("entityList") Collection<T> entityList);

    int updateBatchById(@Param("entityList") Collection<T> entityList);

    int deleteBatchByIds(@Param("ids") Collection<? extends Serializable> ids);

}
