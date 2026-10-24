package io.softwarity.granted.jwt;

import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import org.jboss.logging.Logger;

/**
 * A value fetched over HTTP: cached, re-fetched once older than {@code maxAge} or when forced -
 * but never twice within {@code cooldown}. A failed fetch keeps the last known value, so an IdP
 * outage doesn't turn every caller anonymous. Concurrent callers share one fetch.
 */
final class Fetched<T> {

    private static final Logger LOG = Logger.getLogger(Fetched.class);

    private final JwtSettings.Policy policy;

    private final Callable<T> load;

    private final Supplier<String> failure;

    private final LongSupplier clock;

    private volatile T value;

    /** Last successful fetch - drives {@code maxAge}. */
    private long fetchedAt;

    /** Last fetch attempt, successful or not - drives {@code cooldown}. */
    private long attemptedAt = Long.MIN_VALUE / 2;

    /** Fetch in progress, shared by concurrent callers. */
    private CompletableFuture<T> pending;

    /** Why the last fetch failed; {@code null} once one succeeds. */
    private volatile String lastFailure;

    Fetched(T initial, JwtSettings.Policy policy, Callable<T> load, Supplier<String> failure, LongSupplier clock) {
        this.value = initial;
        this.policy = policy;
        this.load = load;
        this.failure = failure;
        this.clock = clock;
    }

    /** The last known value, without fetching. */
    T value() {
        return value;
    }

    /** Why the last fetch failed - a status, a TLS handshake, a timeout; {@code null} once one succeeds. */
    String lastFailure() {
        return lastFailure;
    }

    T get(boolean force) {
        CompletableFuture<T> shared;
        boolean fetcher = false;
        synchronized (this) {
            long now = clock.getAsLong();
            boolean fresh = fetchedAt > 0 && now - fetchedAt < policy.maxAge();
            if (fresh && !force) {
                return value;
            }
            if (pending == null) {
                if (now - attemptedAt < policy.cooldown()) {
                    return value;
                }
                attemptedAt = now;
                pending = new CompletableFuture<>();
                fetcher = true;
            }
            shared = pending;
        }
        if (!fetcher) {
            return shared.join();
        }
        T result;
        try {
            T loaded = load.call();
            synchronized (this) {
                value = loaded;
                fetchedAt = clock.getAsLong();
            }
            lastFailure = null;
            result = loaded;
        } catch (Exception e) {
            lastFailure = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            LOG.warnf("[quarkus-granted] %s: %s", failure.get(), lastFailure);
            result = value;
        }
        synchronized (this) {
            pending = null;
        }
        shared.complete(result);
        return result;
    }

    /** The URL changed: the next get() fetches, cooldown or not. The last known value stays until then. */
    synchronized void expire() {
        fetchedAt = 0;
        attemptedAt = Long.MIN_VALUE / 2;
    }
}
