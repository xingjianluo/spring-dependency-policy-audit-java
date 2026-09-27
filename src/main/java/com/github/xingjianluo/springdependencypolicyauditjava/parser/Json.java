package com.github.xingjianluo.springdependencypolicyauditjava.parser;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 最小本地 JSON 工具：手写递归下降解析器与序列化，不引入任何外部库。
 * 解析错误带行列位置，便于定位畸形清单。
 */
public final class Json {

    private Json() {
    }

    /** 解析 JSON 文本为 Map/List/String/Double/Boolean/null。 */
    public static Object parse(String text) {
        if (text == null) {
            throw new JsonParseException("JSON 内容为空", 1, 1);
        }
        Parser p = new Parser(text);
        p.skipWhitespace();
        Object value = p.readValue();
        p.skipWhitespace();
        if (!p.atEnd()) {
            throw new JsonParseException("文档结束后仍有多余字符", p.line(), p.column());
        }
        return value;
    }

    /** 将对象序列化为紧凑 JSON。 */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asMap(Object value) {
        if (!(value instanceof Map<?, ?>)) {
            throw new JsonParseException("期望 JSON 对象，实际为 " + typeName(value), 0, 0);
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asList(Object value) {
        if (!(value instanceof List<?>)) {
            throw new JsonParseException("期望 JSON 数组，实际为 " + typeName(value), 0, 0);
        }
        return (List<Object>) value;
    }

    public static String asString(Object value) {
        return value == null ? null : value.toString();
    }

    private static String typeName(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof Map) {
            return "object";
        }
        if (value instanceof List) {
            return "array";
        }
        return value.getClass().getSimpleName();
    }

    private static void writeValue(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String s) {
            writeString(sb, s);
        } else if (value instanceof Boolean b) {
            sb.append(b.booleanValue());
        } else if (value instanceof Number n) {
            double d = n.doubleValue();
            if (d == Math.rint(d) && !Double.isInfinite(d)
                    && n.doubleValue() >= Long.MIN_VALUE && n.doubleValue() <= Long.MAX_VALUE) {
                sb.append(n.longValue());
            } else {
                sb.append(n);
            }
        } else if (value instanceof Map<?, ?> map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                writeValue(sb, e.getValue());
            }
            sb.append('}');
        } else if (value instanceof List<?> list) {
            sb.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeValue(sb, item);
            }
            sb.append(']');
        } else {
            writeString(sb, value.toString());
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    /** JSON 解析异常：携带行列位置。 */
    public static class JsonParseException extends RuntimeException {
        private final int line;
        private final int column;

        public JsonParseException(String message, int line, int column) {
            super(message + " (行 " + line + ", 列 " + column + ")");
            this.line = line;
            this.column = column;
        }

        public int line() {
            return line;
        }

        public int column() {
            return column;
        }
    }

    private static final class Parser {
        private final String text;
        private int pos;

        private Parser(String text) {
            this.text = text;
        }

        boolean atEnd() {
            return pos >= text.length();
        }

        int line() {
            int line = 1;
            for (int i = 0; i < pos && i < text.length(); i++) {
                if (text.charAt(i) == '\n') {
                    line++;
                }
            }
            return line;
        }

        int column() {
            int col = 1;
            for (int i = 0; i < pos && i < text.length(); i++) {
                if (text.charAt(i) == '\n') {
                    col = 1;
                } else {
                    col++;
                }
            }
            return col;
        }

        void skipWhitespace() {
            while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
                pos++;
            }
        }

        char peek() {
            if (atEnd()) {
                throw new JsonParseException("意外到达文件末尾", line(), column());
            }
            return text.charAt(pos);
        }

        Object readValue() {
            skipWhitespace();
            char c = peek();
            return switch (c) {
                case '{' -> readObject();
                case '[' -> readArray();
                case '"' -> readString();
                case 't', 'f' -> readBoolean();
                case 'n' -> readNull();
                default -> {
                    if (c == '-' || Character.isDigit(c)) {
                        yield readNumber();
                    }
                    throw new JsonParseException("无法识别的 JSON 值，起始字符 '" + c + "'", line(), column());
                }
            };
        }

        Map<String, Object> readObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++; // {
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                if (peek() != '"') {
                    throw new JsonParseException("对象键必须是字符串", line(), column());
                }
                String key = readString();
                skipWhitespace();
                if (peek() != ':') {
                    throw new JsonParseException("对象键后期望 ':'", line(), column());
                }
                pos++;
                Object value = readValue();
                map.put(key, value);
                skipWhitespace();
                char next = peek();
                if (next == ',') {
                    pos++;
                } else if (next == '}') {
                    pos++;
                    return map;
                } else {
                    throw new JsonParseException("对象成员之间期望 ',' 或 '}'", line(), column());
                }
            }
        }

        List<Object> readArray() {
            List<Object> list = new ArrayList<>();
            pos++; // [
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(readValue());
                skipWhitespace();
                char next = peek();
                if (next == ',') {
                    pos++;
                } else if (next == ']') {
                    pos++;
                    return list;
                } else {
                    throw new JsonParseException("数组元素之间期望 ',' 或 ']'", line(), column());
                }
            }
        }

        String readString() {
            pos++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw new JsonParseException("字符串缺少结束引号", line(), column());
                }
                char c = text.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (atEnd()) {
                        throw new JsonParseException("转义序列不完整", line(), column());
                    }
                    char e = text.charAt(pos++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            if (pos + 4 > text.length()) {
                                throw new JsonParseException("Unicode 转义不完整", line(), column());
                            }
                            String hex = text.substring(pos, pos + 4);
                            try {
                                sb.append((char) Integer.parseInt(hex, 16));
                            } catch (NumberFormatException nfe) {
                                throw new JsonParseException("非法 Unicode 转义 \\u" + hex, line(), column());
                            }
                            pos += 4;
                        }
                        default -> throw new JsonParseException("非法转义字符 \\" + e, line(), column());
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        Boolean readBoolean() {
            if (text.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (text.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new JsonParseException("非法字面量", line(), column());
        }

        Object readNull() {
            if (text.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new JsonParseException("非法字面量", line(), column());
        }

        Number readNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            readDigits();
            boolean isDouble = false;
            if (!atEnd() && text.charAt(pos) == '.') {
                isDouble = true;
                pos++;
                readDigits();
            }
            if (!atEnd() && (text.charAt(pos) == 'e' || text.charAt(pos) == 'E')) {
                isDouble = true;
                pos++;
                if (!atEnd() && (text.charAt(pos) == '+' || text.charAt(pos) == '-')) {
                    pos++;
                }
                readDigits();
            }
            String token = text.substring(start, pos);
            try {
                // 注意：不能用三元表达式，否则 double/long 会发生数字类型统一，整数被提升为 Double
                if (isDouble) {
                    return Double.valueOf(Double.parseDouble(token));
                }
                return Long.valueOf(Long.parseLong(token));
            } catch (NumberFormatException e) {
                throw new JsonParseException("非法数字 " + token, line(), column());
            }
        }

        void readDigits() {
            int start = pos;
            while (!atEnd() && Character.isDigit(text.charAt(pos))) {
                pos++;
            }
            if (start == pos) {
                throw new JsonParseException("期望数字", line(), column());
            }
        }
    }
}
