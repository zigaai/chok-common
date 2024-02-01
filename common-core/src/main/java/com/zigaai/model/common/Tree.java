package com.zigaai.model.common;

import java.util.List;

public interface Tree<K, T extends Tree<K, T>> {

    K getId();

    K getParentId();

    List<T> getChildren();

    void setChildren(List<T> children);
}
