package com.zigaai.utils;

import com.zigaai.model.common.Tree;
import lombok.experimental.UtilityClass;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@UtilityClass
public final class TreeUtil {

    public static <K, T extends Tree<K, T>> Tree<K, T> listToTree(Collection<T> list, T root) {
        Map<K, T> map = HashMap.newHashMap(list.size() + 1);
        for (T item : list) {
            map.put(item.getId(), item);
        }
        map.put(root.getId(), root);
        for (T item : list) {
            T current = map.get(item.getId());
            T parent = map.get(item.getParentId());
            if (parent != null) {
                if (parent.getChildren() == null) {
                    parent.setChildren(new ArrayList<>());
                }
                parent.getChildren().add(current);
            }
        }
        return root;
    }
}
