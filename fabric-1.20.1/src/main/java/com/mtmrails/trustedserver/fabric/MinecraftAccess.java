package com.mtmrails.trustedserver.fabric;

import com.mojang.authlib.GameProfile;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import net.minecraft.network.Connection;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.protocol.login.ClientboundCustomQueryPacket;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;

/**
 * 隔离 Minecraft 小版本间频繁改名或移到父类的网络字段。
 *
 * <p>1.20.1 的登录档案名为 {@code gameProfile}，1.20.2+ 改为
 * {@code authenticatedProfile}；游戏连接也在 1.20.2 移入公共监听器父类。这里按字段类型与状态枚举常量名定位，
 * 避免把这些名称差异扩散到认证流程。
 */
public final class MinecraftAccess {
    private static volatile Field loginProfileField;
    private static volatile Field loginStateField;

    private MinecraftAccess() {
    }

    /** ResourceLocation 的单字符串构造器在 1.21 变为私有，tryParse 在全部目标版本中保持可用。 */
    public static ResourceLocation resourceLocation(String value) {
        ResourceLocation result = ResourceLocation.tryParse(value);
        if (result == null) {
            throw new IllegalArgumentException("invalid resource location " + value);
        }
        return result;
    }

    public static Connection connection(Object listener) {
        Field field = findField(listener.getClass(), Connection.class);
        try {
            return (Connection) field.get(listener);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("cannot access Minecraft connection", e);
        }
    }

    public static GameProfile loginProfile(ServerLoginPacketListenerImpl listener) {
        try {
            return (GameProfile) loginProfileField().get(listener);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("cannot access Minecraft login profile", e);
        }
    }

    /** 兼容 1.20.1 的 identifier 字段和 1.20.2+ 的 CustomQueryPayload 包装。 */
    public static ResourceLocation loginQueryId(ClientboundCustomQueryPacket packet) {
        ResourceLocation direct = fieldValue(packet, ResourceLocation.class);
        if (direct != null) {
            return direct;
        }
        for (Field field : packet.getClass().getDeclaredFields()) {
            if (field.getType().isPrimitive()) {
                continue;
            }
            Object payload = read(field, packet);
            if (payload == null) {
                continue;
            }
            ResourceLocation nested = fieldValue(payload, ResourceLocation.class);
            if (nested != null) {
                return nested;
            }
            for (Method method : payload.getClass().getMethods()) {
                if (method.getParameterCount() == 0 && method.getReturnType() == ResourceLocation.class) {
                    try {
                        return (ResourceLocation) method.invoke(payload);
                    } catch (IllegalAccessException | InvocationTargetException e) {
                        throw new IllegalStateException("cannot access login query id", e);
                    }
                }
            }
        }
        throw new IllegalStateException("cannot locate Minecraft login query id");
    }

    /** 1.20.1 的 query 直接持有引用计数缓冲区；新 payload 没有缓冲区时无需处理。 */
    public static void releaseLoginQuery(ClientboundCustomQueryPacket packet) {
        FriendlyByteBuf direct = fieldValue(packet, FriendlyByteBuf.class);
        if (direct != null) {
            direct.release();
            return;
        }
        for (Field field : packet.getClass().getDeclaredFields()) {
            if (field.getType().isPrimitive()) {
                continue;
            }
            Object payload = read(field, packet);
            FriendlyByteBuf nested = payload == null ? null : fieldValue(payload, FriendlyByteBuf.class);
            if (nested != null) {
                nested.release();
                return;
            }
        }
    }

    /** 把 Mojang session 失败的连接切换为相同用户名的离线档案，并继续当前版本的登录流程。 */
    public static boolean resumeOfflineLogin(ServerLoginPacketListenerImpl listener, GameProfile profile) {
        try {
            loginProfileField().set(listener, profile);
            Field state = loginStateField();
            Object target = resumeState(state.getType());
            if (target == null) {
                return false;
            }
            state.set(listener, target);
            return true;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return false;
        }
    }

    private static Field loginProfileField() {
        Field field = loginProfileField;
        if (field == null) {
            field = findField(ServerLoginPacketListenerImpl.class, GameProfile.class);
            loginProfileField = field;
        }
        return field;
    }

    private static Field loginStateField() {
        Field field = loginStateField;
        if (field == null) {
            for (Field candidate : ServerLoginPacketListenerImpl.class.getDeclaredFields()) {
                if (candidate.getType().isEnum() && resumeState(candidate.getType()) != null) {
                    candidate.setAccessible(true);
                    field = candidate;
                    loginStateField = candidate;
                    break;
                }
            }
        }
        if (field == null) {
            throw new IllegalStateException("cannot locate Minecraft login state");
        }
        return field;
    }

    private static Field findField(Class<?> start, Class<?> type) {
        for (Class<?> current = start; current != null; current = current.getSuperclass()) {
            for (Field candidate : current.getDeclaredFields()) {
                if (candidate.getType() == type) {
                    candidate.setAccessible(true);
                    return candidate;
                }
            }
        }
        throw new IllegalStateException("cannot locate " + type.getSimpleName() + " in " + start.getName());
    }

    private static <T> T fieldValue(Object owner, Class<T> type) {
        for (Class<?> current = owner.getClass(); current != null; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (field.getType() == type) {
                    return type.cast(read(field, owner));
                }
            }
        }
        return null;
    }

    private static Object read(Field field, Object owner) {
        try {
            field.setAccessible(true);
            return field.get(owner);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("cannot access Minecraft field", e);
        }
    }

    /** 1.20.1 的七值 State 与 1.20.2–1.20.4 的八值 State 都在 ordinal 4 继续离线登录。 */
    private static Object resumeState(Class<?> type) {
        Object[] constants = type.getEnumConstants();
        if (constants == null || (constants.length != 7 && constants.length != 8)) {
            return null;
        }
        return constants[4];
    }
}
