package com.catswords.caterpillar;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONObject;
import javax.servlet.jsp.JspWriter;

public class Worker {

    @SuppressWarnings("unused")
    private static class JsonRpc2 {
        public class Call {
            public Call(Map<String, String> params, String id, String method) {
                this.params = params;
                this.id = id;
                this.method = method;
            }
            public final String jsonrpc = "2.0";
            public String id;
            public String method;
            public Map<String, String> params;
            public String toString() {
                return (new JSONObject(this)).toString();
            }
        }

        public class Error {
            public Error(Map<String, String> error, String id) {
                this.error = error;
                this.id = id;
            }
            public final String jsonrpc = "2.0";
            public String id;
            public Map<String, String> error;
            public String toString() {
                return (new JSONObject(this)).toString();
            }
        }

        public class Result {
            public Result(Map<String, String> result, String id) {
                this.result = result;
                this.id = id;
            }
            public final String jsonrpc = "2.0";
            public String id;
            public Map<String, String> result;
            public String toString() {
                return (new JSONObject(this)).toString();
            }
        }
    }

    private static Map<String, String> parseHeaders(String str) {
        Map<String, String> headers = new HashMap<>();
        String[] lines = str.split("\r?\n");
        String firstLine = lines[0];
        headers.put("@method", firstLine.split(" ")[0]);
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            Matcher matcher = Pattern.compile("^([^:]+):(.*)$").matcher(line);
            if (matcher.matches()) {
                headers.put(matcher.group(1), matcher.group(2).trim());
            }
        }
        return headers;
    }

    private static readFromRemoteServer(String remoteAddress, int remotePort, String scheme, byte[] requestData, object _out, int bufferSize, String id) {
        JspWriter jspWriterOut = (out instanceof JspWriter ? (JspWriter) _out : null);
        Socket conn = (out instanceof Socket ? (Socket) _out : null);
    
        char[] buffer = new char[bufferSize];
        int bytesRead;
    
        try {
            // connect to the remote server
            Socket sock = new Socket();
            sock.connect(new InetSocketAddress(remoteAddress, remotePort));
            DataOutputStream outRemote = new DataOutputStream(sock.getOutputStream());
            BufferedReader inRemote = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            DataOutputStream outClient = new DataOutputStream(conn.getOutputStream());
            BufferedReader inClient = new BufferedReader(new InputStreamReader(conn.getInputStream()));

            // send data to the remote server
            if (jspWriterOut != null) {
                outRemote.write(requestData, 0, requestData.length);
            } else if (conn != null) {
                while ((bytesRead = inClient.read(buffer, 0, bufferSize)) != -1) {
                    char[] outBuffer = new char[bytesRead];
                    System.arraycopy(buffer, 0, outBuffer, 0, bytesRead);
                    outRemote.write(outBuffer);
                }
            }

            // receive a response and forward to the client
            while ((bytesRead = inRemote.read(buffer, 0, bufferSize)) != -1) {
                if (jspWriterOut != null) {
                    out.write(buffer, 0, bytesRead);
                } else if (conn != null) {
                    char[] outBuffer = new char[bytesRead];
                    System.arraycopy(buffer, 0, outBuffer, 0, bytesRead);
                    outClient.write(outBuffer);
                }
            }
        } catch (Exception e) {
            // build a description of the error
            Map<String, Object> error = new HashMap<>();
            error.put("status", 502);
            error.put("code", e.getMessage());
            error.put("message", e.getMessage());
            String response = new JsonRpc2.Error(error, id);

            // send output to the client
            if (jspWriterOut != null) {
                out.println(response.toString());
            } else if (conn != null) {
                conn.getOutputStream().write(response.toString().getBytes());
            }
        }
    }

    // Stateless (Servlet only)
    public static void relayRequest(Map<String, Object> params, String id, JspWriter out) {
        int bufferSize = Integer.parseInt((String) params.get("buffer_size"));
        byte[] requestData = java.util.Base64.getDecoder().decode((String) params.get("request_data"));
        Map<String, String> requestHeader = parseHeaders(new String(requestData));
        int requestLength = Integer.parseInt((String) params.get("request_length"));
        String clientAddress = (String) params.get("client_address");
        int clientPort = Integer.parseInt((String) params.get("client_port"));
        String clientEncoding = (String) params.get("client_encoding");
        String remoteAddress = (String) params.get("remote_address");
        int remotePort = Integer.parseInt((String) params.get("remote_port"));
        String scheme = (String) params.get("scheme");
        String datetime = (String) params.get("datetime");

        switch (requestHeader.get("@method")) {
            case "CONNECT":
                Map<String, Object> error = new HashMap<>();
                error.put("status", 405);
                error.put("code", -1);
                error.put("message", "Method Not Allowed");
                out.println((new JsonRpc2.Error(error, id)).toString());
                break;

            default:
                readFromRemoteServer(remoteAddress, remotePort, scheme, requestData, out, bufferSize, id);
        }
    }

    // Stateful mode (Servlet + Socket combination)
    public static void relayConenct(Map<String, Object> params, String id, JspWriter out) {
        int bufferSize = Integer.parseInt((String) params.get("buffer_size"));
        String clientAddress = (String) params.get("client_address");
        int clientPort = Integer.parseInt((String) params.get("client_port"));
        String clientEncoding = (String) params.get("client_encoding");
        String remoteAddress = (String) params.get("remote_address");
        int remotePort = Integer.parseInt((String) params.get("remote_port"));
        String scheme = (String) params.get("scheme");
        String datetime = (String) params.get("datetime");

        long startTime = System.currentTimeMillis();
        try {
            Socket conn = new Socket(clientAddress, clientPort);

            long stopTime = System.currentTimeMillis();
            long connectionSpeed = stopTime - startTime;
            JSONObject data = new JSONObject();
            data.put("success", true);
            data.put("connection_speed", connectionSpeed);
            String jsonData = JsonPpc2.Call("relay_accept", data, id).toString();

            DataOutputStream outToClient = new DataOutputStream(conn.getOutputStream());
            outToClient.writeBytes(jsonData + "\r\n\r\n");

            readFromRemoteServer(remoteAddress, remotePort, scheme, null, conn, bufferSize, id);
            conn.close();
        } catch (Exception e) {
            JSONObject error = new JSONObject();
            error.put("status", 502);
            error.put("code", e.getMessage());
            error.put("message", e.getMessage());
            error.put("_params", params);
            out.println(new JsonRpc2.Error(error, id)).toString();
        }
    }
}
