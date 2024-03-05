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

        public static String encode(Map<String, String> params, String id, String method) {
            return (new Call(params, id, method)).toString();
        }

        public static String errorEncode(Map<String, String> error, String id) {
            return (new Error(error, id)).toString();
        }

        public static String resultEncode(Map<String, String> result, String id) {
            return (new Result(result, id)).toString();
        }
    }

    public static Map<String, String> parseHeaders(String str) {
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
        try {
            Socket sock = new Socket();
            sock.connect(new InetSocketAddress(remoteAddress, remotePort));
            DataOutputStream outToServer = new DataOutputStream(sock.getOutputStream());
            BufferedReader inFromServer = new BufferedReader(new InputStreamReader(sock.getInputStream()));

            outToServer.write(requestData, 0, sendData.length);

            char[] buffer = new char[bufferSize];
            int bytesRead;
            StringBuilder response = new StringBuilder();
            while ((bytesRead = inFromServer.read(buffer, 0, bufferSize)) != -1) {
                response.append(buffer, 0, bytesRead);
            }

            if (out instanceof JspWriter) {
                JspWriter out = (JspWriter) _out;
                out.println(response.toString());
            } else if (out instanceof Socket) {
                Socket conn = (Socket) _out;
                conn.getOutputStream().write(response.toString().getBytes());
            }
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", 502);
            error.put("code", e.getMessage());
            error.put("message", e.getMessage());
            String response = new JsonRpc2.Error(error, id);
            if (out instanceof JspWriter) {
                JspWriter out = (JspWriter) _out;
                out.println(response.toString());
            } else if (out instanceof Socket) {
                Socket conn = (Socket) _out;
                conn.getOutputStream().write(response.toString().getBytes());
            }
        }
    }

    // Stateless (Servlet only)
    public static void relayRequest(Map<String, Object> params, String id, JspWriter out) throws Exception {
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
                out.println(JsonRpc2.errorEncode(error, id));
                break;
            default:
                readFromRemoteServer(remoteAddress, remotePort, scheme, requestData, out, bufferSize, id);
        }
        
    }

    // Stateful (Servlet only)
    public static void relayConenct(Map<String, Object> params, String id, JspWriter out) throws Exception {
        // todo
    }

    // Stateful (Socket only)
    public static void relayConenct(Map<String, Object> params, String id, Socket connection) throws Exception {
        // todo
    }

}
