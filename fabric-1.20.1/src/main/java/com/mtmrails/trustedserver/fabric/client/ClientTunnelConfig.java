package com.mtmrails.trustedserver.fabric.client;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** 客户端是否在服务端 optional 时请求全连接隧道。 */
record ClientTunnelConfig(boolean wantTunnel) {
    static ClientTunnelConfig loadOrCreate(Path file) throws IOException {
        if (!Files.exists(file)) {
            Files.createDirectories(file.toAbsolutePath().getParent());
            JsonObject defaults = new JsonObject();
            defaults.addProperty("wantTunnel", false);
            Files.writeString(file,
                    new GsonBuilder().setPrettyPrinting().create().toJson(defaults) + "\n",
                    StandardCharsets.UTF_8);
            return new ClientTunnelConfig(false);
        }
        try {
            JsonElement root = JsonParser.parseString(Files.readString(file, StandardCharsets.UTF_8));
            if (!root.isJsonObject()) {
                throw new IOException("client.json top level must be an object");
            }
            JsonElement value = root.getAsJsonObject().get("wantTunnel");
            if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
                throw new IOException("client.json wantTunnel must be boolean");
            }
            return new ClientTunnelConfig(value.getAsBoolean());
        } catch (JsonParseException | IllegalStateException e) {
            throw new IOException("client.json is invalid", e);
        }
    }
}
