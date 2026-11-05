package com.mtmrails.trustedserver.server.config;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 带路径的 JSON 读取：缺少的键用默认值，类型或范围不对抛出带完整路径的 {@link ConfigException}，
 * 并记录读过的键以便报告未知键。只用 Gson 2.8.9 已有的 API。
 */
final class JsonSection {
    private final JsonObject object;
    private final String path;
    private final Set<String> seen = new HashSet<>();
    private final Map<String, JsonSection> children = new java.util.LinkedHashMap<>();

    JsonSection(JsonObject object, String path) {
        this.object = object;
        this.path = path;
    }

    private String at(String key) {
        return path.isEmpty() ? key : path + "." + key;
    }

    /** 同一个键多次调用返回同一个子节点，读过的键因此不会被误报为未知。 */
    JsonSection section(String key) throws ConfigException {
        JsonSection cached = children.get(key);
        if (cached != null) {
            return cached;
        }
        seen.add(key);
        JsonElement element = object.get(key);
        JsonObject child;
        if (element == null || element.isJsonNull()) {
            child = new JsonObject();
        } else if (element.isJsonObject()) {
            child = element.getAsJsonObject();
        } else {
            throw new ConfigException(at(key) + ": expected an object");
        }
        JsonSection section = new JsonSection(child, at(key));
        children.put(key, section);
        return section;
    }

    int integer(String key, int def, int min, int max) throws ConfigException {
        JsonPrimitive p = primitive(key);
        if (p == null) {
            return def;
        }
        if (!p.isNumber()) {
            throw new ConfigException(at(key) + ": expected an integer");
        }
        double d = p.getAsDouble();
        if (d != Math.rint(d) || d < min || d > max) {
            throw new ConfigException(at(key) + ": must be an integer between " + min + " and " + max);
        }
        return (int) d;
    }

    boolean bool(String key, boolean def) throws ConfigException {
        JsonPrimitive p = primitive(key);
        if (p == null) {
            return def;
        }
        if (!p.isBoolean()) {
            throw new ConfigException(at(key) + ": expected true or false");
        }
        return p.getAsBoolean();
    }

    String string(String key, String def) throws ConfigException {
        JsonPrimitive p = primitive(key);
        if (p == null) {
            return def;
        }
        if (!p.isString()) {
            throw new ConfigException(at(key) + ": expected a string");
        }
        return p.getAsString();
    }

    <E extends Enum<E>> E enumValue(String key, E def, Class<E> type) throws ConfigException {
        String value = string(key, null);
        if (value == null) {
            return def;
        }
        try {
            return Enum.valueOf(type, value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            List<String> allowed = new ArrayList<>();
            for (E constant : type.getEnumConstants()) {
                allowed.add(constant.name().toLowerCase(Locale.ROOT));
            }
            throw new ConfigException(at(key) + ": must be one of " + allowed);
        }
    }

    List<String> stringList(String key) throws ConfigException {
        seen.add(key);
        JsonElement element = object.get(key);
        List<String> out = new ArrayList<>();
        if (element == null || element.isJsonNull()) {
            return out;
        }
        if (!element.isJsonArray()) {
            throw new ConfigException(at(key) + ": expected an array of strings");
        }
        JsonArray array = element.getAsJsonArray();
        for (int i = 0; i < array.size(); i++) {
            JsonElement item = array.get(i);
            if (!item.isJsonPrimitive() || !item.getAsJsonPrimitive().isString()) {
                throw new ConfigException(at(key) + "[" + i + "]: expected a string");
            }
            out.add(item.getAsString());
        }
        return out;
    }

    /** 抛出带路径的错误（供调用方做跨字段校验）。 */
    ConfigException error(String key, String message) {
        return new ConfigException(at(key) + ": " + message);
    }

    void collectUnknown(List<String> out) {
        for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
            if (!seen.contains(entry.getKey())) {
                out.add(at(entry.getKey()));
            }
        }
        for (JsonSection child : children.values()) {
            child.collectUnknown(out);
        }
    }

    private JsonPrimitive primitive(String key) throws ConfigException {
        seen.add(key);
        JsonElement element = object.get(key);
        if (element == null || element.isJsonNull()) {
            return null;
        }
        if (!element.isJsonPrimitive()) {
            throw new ConfigException(at(key) + ": expected a value, not " + (element.isJsonObject() ? "an object"
                    : "an array"));
        }
        return element.getAsJsonPrimitive();
    }
}
