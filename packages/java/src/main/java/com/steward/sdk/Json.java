package com.steward.sdk;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class Json {
    private Json() {
    }

    static String stringify(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out);
        return out.toString();
    }

    static Object parse(String json) {
        return new Parser(json).parse();
    }

    private static void write(Object value, StringBuilder out) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String string) {
            writeString(string, out);
        } else if (value instanceof Number || value instanceof Boolean) {
            out.append(value);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            List<Map.Entry<String, Object>> entries = new ArrayList<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getValue() != null) {
                    entries.add(Map.entry(String.valueOf(entry.getKey()), entry.getValue()));
                }
            }
            entries.sort(Comparator.comparing(Map.Entry::getKey));
            for (int i = 0; i < entries.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                writeString(entries.get(i).getKey(), out);
                out.append(':');
                write(entries.get(i).getValue(), out);
            }
            out.append('}');
        } else if (value instanceof Iterable<?> iterable) {
            out.append('[');
            int i = 0;
            for (Object item : iterable) {
                if (i++ > 0) {
                    out.append(',');
                }
                write(item, out);
            }
            out.append(']');
        } else if (value.getClass().isArray()) {
            out.append('[');
            int length = java.lang.reflect.Array.getLength(value);
            for (int i = 0; i < length; i++) {
                if (i > 0) {
                    out.append(',');
                }
                write(java.lang.reflect.Array.get(value, i), out);
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("Unsupported JSON value type: " + value.getClass().getName());
        }
    }

    private static void writeString(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static final class Parser {
        private final String json;
        private int pos;

        Parser(String json) {
            this.json = json;
        }

        Object parse() {
            Object value = readValue();
            skipWhitespace();
            if (pos != json.length()) {
                throw new IllegalArgumentException("Unexpected trailing JSON at position " + pos);
            }
            return value;
        }

        private Object readValue() {
            skipWhitespace();
            if (pos >= json.length()) {
                throw new IllegalArgumentException("Unexpected end of JSON");
            }
            char c = json.charAt(pos);
            if (c == '"') {
                return readString();
            }
            if (c == '{') {
                return readObject();
            }
            if (c == '[') {
                return readArray();
            }
            if (c == 't' && json.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (c == 'f' && json.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            if (c == 'n' && json.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            return readNumber();
        }

        private Map<String, Object> readObject() {
            pos++;
            Map<String, Object> object = new LinkedHashMap<>();
            skipWhitespace();
            if (consume('}')) {
                return object;
            }
            do {
                skipWhitespace();
                String key = readString();
                skipWhitespace();
                expect(':');
                object.put(key, readValue());
                skipWhitespace();
            } while (consume(','));
            expect('}');
            return object;
        }

        private List<Object> readArray() {
            pos++;
            List<Object> array = new ArrayList<>();
            skipWhitespace();
            if (consume(']')) {
                return array;
            }
            do {
                array.add(readValue());
                skipWhitespace();
            } while (consume(','));
            expect(']');
            return array;
        }

        private String readString() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (pos < json.length()) {
                char c = json.charAt(pos++);
                if (c == '"') {
                    return out.toString();
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (pos >= json.length()) {
                    throw new IllegalArgumentException("Invalid JSON escape");
                }
                char escaped = json.charAt(pos++);
                switch (escaped) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        String hex = json.substring(pos, pos + 4);
                        out.append((char) Integer.parseInt(hex, 16));
                        pos += 4;
                    }
                    default -> throw new IllegalArgumentException("Invalid JSON escape: " + escaped);
                }
            }
            throw new IllegalArgumentException("Unterminated JSON string");
        }

        private Number readNumber() {
            int start = pos;
            while (pos < json.length()) {
                char c = json.charAt(pos);
                if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
                    pos++;
                } else {
                    break;
                }
            }
            String raw = json.substring(start, pos);
            if (raw.contains(".") || raw.contains("e") || raw.contains("E")) {
                return new BigDecimal(raw);
            }
            try {
                return Long.parseLong(raw);
            } catch (NumberFormatException ignored) {
                return new BigDecimal(raw);
            }
        }

        private void skipWhitespace() {
            while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) {
                pos++;
            }
        }

        private boolean consume(char expected) {
            if (pos < json.length() && json.charAt(pos) == expected) {
                pos++;
                return true;
            }
            return false;
        }

        private void expect(char expected) {
            if (!consume(expected)) {
                throw new IllegalArgumentException("Expected '" + expected + "' at position " + pos);
            }
        }
    }
}
