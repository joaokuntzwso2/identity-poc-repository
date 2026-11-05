package com.magalu.wso2.risk;

/** Implementers must not block authentication threads or record raw identifiers. */
@FunctionalInterface
public interface EventSink { void submit(Signal signal, Decision decision); }
