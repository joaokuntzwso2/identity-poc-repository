package com.magalu.wso2.risk;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;

/** Separate risk-owned Postgres schema; pooled, capped, timeout-bound JDBC. Never WSO2 tables.
 * Requires JDBC URL connectTimeout=1&socketTimeout=1&tcpKeepAlive=true, protected TLS connection.
 */
public final class PgStore implements Store, AutoCloseable {
    private final ArrayBlockingQueue<Connection> pool;
    public PgStore(String url, String user, String password, int connections) throws SQLException {
        if (connections<1 || connections>12 || !url.startsWith("jdbc:postgresql:")
                || !url.contains("connectTimeout=") || !url.contains("socketTimeout=")) {
            throw new IllegalArgumentException("bounded PostgreSQL JDBC URL and pool required");
        }
        pool=new ArrayBlockingQueue<>(connections);
        try { Class.forName("org.postgresql.Driver"); }
        catch(ClassNotFoundException ex) {throw new SQLException("PostgreSQL JDBC driver not bundled",ex);}
        try {
            for(int i=0;i<connections;i++) {
                Connection c=DriverManager.getConnection(url,user,password);
                c.setReadOnly(false); pool.add(c);
            }
        } catch(SQLException ex) { close(); throw ex; }
    }
    private Connection acquire() throws Exception {
        Connection c=pool.poll(25,TimeUnit.MILLISECONDS);
        if(c==null) throw new SQLException("risk-state pool saturated");
        return c;
    }
    private void release(Connection c) { if(c!=null && !pool.offer(c)) try { c.close(); } catch(SQLException ignored){} }
    private static void timeout(Connection c) throws SQLException {
        try(Statement st=c.createStatement()) { st.execute("SET statement_timeout = 200"); }
    }
    @Override public List<Signal> recent(Policy p,long now) throws Exception {
        Connection c=acquire();
        try {
            timeout(c);
            String q="SELECT tenant,account_key,ip_key,network_key,device_key,session_key,agent_key,event_ms,outcome,automation,challenge_failed "
                    +"FROM magalu_risk.events WHERE tenant=? AND event_ms>=? AND event_ms<=? "
                    +"ORDER BY event_ms DESC LIMIT ?";
            try (PreparedStatement ps=c.prepareStatement(q)) {
                ps.setString(1,p.tenant); ps.setLong(2,now-p.windowSeconds*1000L);ps.setLong(3,now);
                ps.setInt(4,p.maxEvents+1);
                try(ResultSet rs=ps.executeQuery()) {
                    List<Signal> results=read(rs);
                    if(results.size()>p.maxEvents) throw new SQLException("risk event window saturated; fail-safe");
                    return results;
                }
            }
        } finally { release(c); }
    }
    @Override public List<Signal> baseline(Policy p,String account,long now) throws Exception {
        if(account==null)return List.of();
        Connection c=acquire();
        try {
            timeout(c);
            String q="SELECT tenant,account_key,ip_key,network_key,device_key,session_key,agent_key,event_ms,outcome,automation,challenge_failed "
                    +"FROM magalu_risk.events WHERE tenant=? AND account_key=? AND outcome='SUCCESS' "
                    +"AND event_ms>=? AND event_ms<? ORDER BY event_ms DESC LIMIT 512";
            try(PreparedStatement ps=c.prepareStatement(q)) {
                ps.setString(1,p.tenant);ps.setString(2,account);ps.setLong(3,now-p.baselineDays*86400000L);ps.setLong(4,now);
                try(ResultSet rs=ps.executeQuery()) {return read(rs);}
            }
        } finally { release(c); }
    }
    @Override public void record(Signal s) throws Exception {
        Connection c=acquire();
        try {
            timeout(c);
            try(PreparedStatement ps=c.prepareStatement("INSERT INTO magalu_risk.events "
                    +"(tenant,account_key,ip_key,network_key,device_key,session_key,agent_key,event_ms,outcome,automation,challenge_failed) "
                    +"VALUES (?,?,?,?,?,?,?,?,?,?,?)")) {
                ps.setString(1,s.tenant);ps.setString(2,s.account);ps.setString(3,s.ip);
                ps.setString(4,s.network);ps.setString(5,s.device);ps.setString(6,s.session);
                ps.setString(7,s.agent);ps.setLong(8,s.epochMillis);ps.setString(9,s.outcome.name());
                ps.setBoolean(10,s.automation);ps.setBoolean(11,s.challengeFailed);ps.executeUpdate();
            }
        } finally { release(c); }
    }
    private static List<Signal> read(ResultSet rs) throws SQLException {
        List<Signal> out=new ArrayList<>();
        while(rs.next()) out.add(new Signal(rs.getString(1),rs.getString(2),rs.getString(3),
                rs.getString(4),rs.getString(5),rs.getString(6),rs.getString(7),rs.getLong(8),
                Signal.Outcome.valueOf(rs.getString(9)),rs.getBoolean(10),rs.getBoolean(11)));
        return out;
    }
    @Override public void close() {
        Connection c;
        while((c=pool.poll())!=null) try{c.close();}catch(SQLException ignored){}
    }
}
