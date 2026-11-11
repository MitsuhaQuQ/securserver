package com.mtmrails.trustedserver.fabric.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class I18nResourcesTest {
    private static final String[] LOCALES = {"en_us", "zh_cn", "zh_tw", "ja_jp"};
    private static final Pattern PLACEHOLDER = Pattern.compile("%(?:(\\d+)\\$)?s");

    @Test
    void everyLocaleHasTheSameNonBlankKeysAndPlaceholders() {
        JsonObject base = load(LOCALES[0]);
        Set<String> expected = base.keySet();
        for (String locale : LOCALES) {
            JsonObject translations = load(locale);
            assertEquals(expected, translations.keySet(), locale + " translation keys");
            for (Map.Entry<String, JsonElement> entry : translations.entrySet()) {
                String value = entry.getValue().getAsString();
                assertFalse(value.isBlank(), locale + ":" + entry.getKey());
                assertEquals(placeholders(base.get(entry.getKey()).getAsString()), placeholders(value),
                        locale + ":" + entry.getKey() + " placeholders");
            }
        }
    }

    private static JsonObject load(String locale) {
        String path = "/assets/trustedserver/lang/" + locale + ".json";
        var stream = I18nResourcesTest.class.getResourceAsStream(path);
        assertNotNull(stream, path);
        try (var reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
            return JsonParser.parseReader(reader).getAsJsonObject();
        } catch (Exception e) {
            throw new AssertionError("Cannot read " + path, e);
        }
    }

    private static List<String> placeholders(String value) {
        return PLACEHOLDER.matcher(value).results().map(result -> result.group()).toList();
    }
}
