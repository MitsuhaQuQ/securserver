package com.mtmrails.trustedserver.server.store;

/** audit_log 的一行。 */
public record AuditRecord(long timestamp, String subject, String event, String ip, String detail) {
}
