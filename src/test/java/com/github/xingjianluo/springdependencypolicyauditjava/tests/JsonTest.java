package com.github.xingjianluo.springdependencypolicyauditjava.tests;

import com.github.xingjianluo.springdependencypolicyauditjava.parser.Json;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonTest {

    @Test
    void parsesNestedStructure() {
        Object root = Json.parse("{\"a\":1,\"b\":[true,false,null,\"s\"],\"c\":{\"d\":2.5}}");
        Map<String, Object> map = Json.asMap(root);
        assertEquals(1L, map.get("a"));
        // Arrays.asList 允许 null 元素
        assertEquals(Arrays.asList(true, false, null, "s"), map.get("b"));
        assertEquals(2.5, ((Map<?, ?>) map.get("c")).get("d"));
    }

    @Test
    void roundTrip() {
        Map<String, Object> map = Map.of("k", "v", "n", 1L, "arr", Arrays.asList(1L, 2L));
        Object reparsed = Json.parse(Json.write(map));
        // 比较条目内容，忽略 LinkedHashMap / 不可变 Map 的实现差异
        assertEquals(map, reparsed);
    }

    @Test
    void malformedJsonThrowsWithPosition() {
        Json.JsonParseException ex = assertThrows(Json.JsonParseException.class,
                () -> Json.parse("{\"a\": }"));
        assertTrue(ex.line() >= 1 && ex.column() >= 1);
        assertTrue(ex.getMessage().contains("行"));
    }

    @Test
    void trailingCharactersRejected() {
        assertThrows(Json.JsonParseException.class, () -> Json.parse("{} garbage"));
    }

    @Test
    void emptyRejected() {
        assertThrows(Json.JsonParseException.class, () -> Json.parse(""));
    }
}
