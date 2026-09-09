package com.shellsight.javamem;

/**
 * The two hard limits Stage 4 runs under, and the record of which one stopped it.
 *
 * <p>"Low overhead" and "does not disturb the live server" are promises made to an operator about
 * a production JVM. A promise enforced by a comment is not enforced; this class is where they
 * become mechanical.
 *
 * <p>Equally important is {@link #reason()}. A scan that hit its cap saw PART of the JVM, and the
 * report must say so -- reporting a truncated sweep as a complete one is exactly how a scanner
 * comes to claim "clean" about something it never looked at.
 */
final class CaptureBudget {
    private final int maxClasses;
    private final long deadlineNanos;
    private int used;
    private String stopReason = "";

    CaptureBudget(int maxClasses, long budgetMillis) {
        this.maxClasses = maxClasses;
        this.deadlineNanos = System.nanoTime() + budgetMillis * 1_000_000L;
    }

    /** Reserve one capture. Returns false once either limit is reached. */
    boolean tryConsume() {
        if (System.nanoTime() > deadlineNanos) {
            if (stopReason.isEmpty())
                stopReason = "time budget exhausted after " + used + " class(es) captured";
            return false;
        }
        if (used >= maxClasses) {
            if (stopReason.isEmpty())
                stopReason = "class cap reached (" + maxClasses + " classes)";
            return false;
        }
        used++;
        return true;
    }

    boolean exhausted() { return !stopReason.isEmpty(); }
    String  reason()    { return stopReason; }
    int     spent()     { return used; }
}
