package com.magalu.wso2.risk;

import java.util.List;

/** Multi-node implementation must be bounded by deadline and result-row cap. */
public interface Store {
    List<Signal> recent(Policy policy, long now) throws Exception;
    List<Signal> baseline(Policy policy, String account, long now) throws Exception;
    void record(Signal signal) throws Exception;
}
