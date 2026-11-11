package com.mtmrails.trustedserver.fabric.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ClientTunnelConfigTest {
    @TempDir
    Path dir;

    @Test
    void createsDefaultAndReadsPreference() throws Exception {
        Path file = dir.resolve("client.json");
        assertFalse(ClientTunnelConfig.loadOrCreate(file).wantTunnel());
        assertTrue(Files.readString(file).contains("\"wantTunnel\": false"));

        Files.writeString(file, "{\"wantTunnel\":true}\n");
        assertTrue(ClientTunnelConfig.loadOrCreate(file).wantTunnel());
    }

    @Test
    void rejectsMissingOrWrongType() throws Exception {
        Path file = dir.resolve("client.json");
        Files.writeString(file, "{}\n");
        assertThrows(IOException.class, () -> ClientTunnelConfig.loadOrCreate(file));
        Files.writeString(file, "{\"wantTunnel\":\"yes\"}\n");
        assertThrows(IOException.class, () -> ClientTunnelConfig.loadOrCreate(file));
    }
}
