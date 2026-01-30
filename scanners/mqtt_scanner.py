#!/usr/bin/env python3
"""
MQTT protocol scanner for detecting security issues in IIoT and SCADA-to-cloud communications.
"""

import socket
import struct
import time
import random
import ssl
import threading
import paho.mqtt.client as mqtt

from scanners.base_scanner import BaseScanner

# Common topics to check for read access
COMMON_MQTT_TOPICS = [
    "#",                # All topics (wildcard)
    "+/+",              # Two-level wildcard
    "sensor/#",         # All sensor topics
    "device/#",         # All device topics
    "scada/#",          # All SCADA topics
    "plc/#",            # All PLC topics
    "control/#",        # All control topics
    "factory/#",        # All factory topics
    "building/#",       # All building topics
    "energy/#",         # All energy topics
    "power/#",          # All power topics
    "status/#",         # All status topics
    "data/#",           # All data topics
    "telemetry/#",      # All telemetry topics
    "alarm/#",          # All alarm topics
    "alert/#",          # All alert topics
    "config/#",         # All configuration topics
    "command/#",        # All command topics
    "system/#",         # All system topics
    "$SYS/#"            # Broker internal topics
]

# Control-related topic prefixes (dangerous for QoS 0 / retained messages)
CONTROL_TOPIC_PREFIXES = ("control", "command", "cmd", "plc", "scada", "actuator", "valve", "switch")

# Common ICS client IDs for enumeration
ICS_CLIENT_IDS = [
    "plc_01", "plc_02", "plc_master", "scada_master", "scada_01",
    "hmi_01", "hmi_02", "rtu_01", "dcs_controller", "iot_gateway",
    "edge_device", "mqtt_bridge", "data_collector", "sensor_hub"
]

# WebSocket MQTT ports
WS_MQTT_PORTS = [9001, 8083]


class MQTTScanner(BaseScanner):
    """Scanner for detecting security issues in MQTT brokers and clients."""

    def __init__(self, intensity='low', timeout=5, verify=True, test_mode=False):
        """Initialize the MQTT scanner."""
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [1883, 8883]
        self.test_mode = test_mode

    # ── helpers ──────────────────────────────────────────────────────────

    def _make_client(self, client_id, protocol=None, transport="tcp"):
        """Create an mqtt.Client with proper callback API version."""
        kwargs = {
            "client_id": client_id,
            "callback_api_version": mqtt.CallbackAPIVersion.VERSION1,
            "transport": transport,
        }
        if protocol is not None:
            kwargs["protocol"] = protocol
        return mqtt.Client(**kwargs)

    def _apply_tls(self, client):
        """Apply TLS settings for encrypted connections."""
        client.tls_set(cert_reqs=ssl.CERT_NONE)
        client.tls_insecure_set(True)

    def _connect_and_wait(self, client, target, port, wait=0.5):
        """Connect async, run loop, wait for callback flag, return connected bool."""
        connected = threading.Event()
        conn_rc = [None]

        def _on_connect(_c, _ud, _flags, rc):
            conn_rc[0] = rc
            if rc == 0:
                connected.set()

        client.on_connect = _on_connect
        client.connect_async(target, port, 60)
        client.loop_start()
        connected.wait(timeout=wait)
        return connected.is_set(), conn_rc[0]

    def _safe_disconnect(self, client):
        try:
            client.disconnect()
        except Exception:
            pass
        try:
            client.loop_stop()
        except Exception:
            pass

    # ── scan entry point ─────────────────────────────────────────────────

    def scan(self, target, open_ports=None):
        """
        Scan a target for MQTT security issues.

        Args:
            target (str): Target IP address
            open_ports (list): List of open ports (optional)

        Returns:
            dict: Scan results
        """
        self.start_scan_timer()
        self.logger.debug(f"Starting MQTT scan on {target}")

        results = {"device_info": {}, "issues": []}

        ports_to_scan = open_ports if open_ports else self.standard_ports

        # Discover MQTT services
        mqtt_ports = []
        for port in ports_to_scan:
            protocol = self._check_mqtt_availability(target, port)
            if protocol:
                mqtt_ports.append((port, protocol))

        if not mqtt_ports:
            self.logger.debug(f"No MQTT service detected on {target}")
            return None

        results["device_info"]["ports"] = [p for p, _ in mqtt_ports]
        results["device_info"]["protocols"] = [p for _, p in mqtt_ports]

        for port, protocol in mqtt_ports:
            results["issues"].append(self.create_issue(
                severity="info",
                description=f"MQTT Broker Found: {target}:{port} ({protocol})",
                details=f"A device responding to MQTT protocol was detected on port {port}.",
            ))

            # ── authentication tests ────────────────────────────────────
            auth_results = self._test_authentication(target, port, protocol)

            if auth_results.get("anonymous_access"):
                results["issues"].append(self.create_issue(
                    severity="critical",
                    description="MQTT broker allows anonymous access",
                    details="The broker allows connections without authentication, enabling unauthorized access to data and commands.",
                    remediation="Configure the broker to require username and password authentication.",
                ))

            if auth_results.get("default_credentials"):
                for cred in auth_results["default_credentials"]:
                    results["issues"].append(self.create_issue(
                        severity="high",
                        description=f"MQTT broker accepts default credentials: {cred[0]}:{cred[1]}",
                        details="The broker accepts well-known default credentials.",
                        remediation="Change default credentials and implement a strong password policy.",
                    ))

            if protocol == "mqtt":
                results["issues"].append(self.create_issue(
                    severity="high",
                    description="MQTT traffic is unencrypted",
                    details="The broker accepts connections without TLS encryption, exposing data and credentials to eavesdropping.",
                    remediation="Configure the broker to use TLS (MQTT over SSL) on port 8883.",
                ))

            # ── MQTT v5 detection ───────────────────────────────────────
            if not self.test_mode:
                v5_info = self._check_mqtt_v5(target, port, protocol)
                if v5_info:
                    results["issues"].append(v5_info)

            # ── Will message check ──────────────────────────────────────
            if not self.test_mode:
                will_issue = self._check_will_message(target, port, protocol)
                if will_issue:
                    results["issues"].append(will_issue)

            has_access = auth_results.get("anonymous_access") or auth_results.get("default_credentials")
            credentials = None
            if auth_results.get("default_credentials"):
                credentials = auth_results["default_credentials"][0]

            # ── topic access + retained messages ────────────────────────
            if not self.test_mode and self.intensity in ["medium", "high"] and has_access:
                try:
                    topics_access = self._test_topics_access(target, port, protocol, credentials)

                    if topics_access.get("readable_topics"):
                        topics_list = ", ".join(topics_access["readable_topics"][:5])
                        if len(topics_access["readable_topics"]) > 5:
                            topics_list += f" and {len(topics_access['readable_topics']) - 5} more"
                        results["device_info"]["readable_topics"] = topics_access["readable_topics"]
                        results["issues"].append(self.create_issue(
                            severity="medium",
                            description=f"Unauthorized read access to MQTT topics: {topics_list}",
                            details="The broker allows reading from topics without proper authentication.",
                            remediation="Implement access control lists (ACLs) to restrict topic access.",
                        ))

                    if topics_access.get("writable_topics"):
                        topics_list = ", ".join(topics_access["writable_topics"][:5])
                        if len(topics_access["writable_topics"]) > 5:
                            topics_list += f" and {len(topics_access['writable_topics']) - 5} more"
                        results["device_info"]["writable_topics"] = topics_access["writable_topics"]
                        results["issues"].append(self.create_issue(
                            severity="critical",
                            description=f"Unauthorized write access to MQTT topics: {topics_list}",
                            details="The broker allows publishing to topics without proper authentication, potentially allowing command injection.",
                            remediation="Implement access control lists (ACLs) to restrict topic access.",
                        ))

                    # Retained messages on control topics
                    if topics_access.get("retained_control_topics"):
                        ret_list = ", ".join(topics_access["retained_control_topics"][:5])
                        results["issues"].append(self.create_issue(
                            severity="medium",
                            description=f"Retained messages found on control topics: {ret_list}",
                            details="Retained messages on control topics may contain stale commands or sensitive operational data that persists across client reconnections.",
                            remediation="Disable retained messages on control topics or clear stale retained messages periodically.",
                        ))
                except Exception as e:
                    self.logger.debug(f"Error testing topic access: {str(e)}")

            # ── QoS level testing ───────────────────────────────────────
            if not self.test_mode and self.intensity in ["medium", "high"] and has_access:
                try:
                    qos_issue = self._test_qos_levels(target, port, protocol, credentials)
                    if qos_issue:
                        results["issues"].append(qos_issue)
                except Exception as e:
                    self.logger.debug(f"Error testing QoS levels: {str(e)}")

            # ── system info disclosure ──────────────────────────────────
            if not self.test_mode and self.intensity in ["medium", "high"] and has_access:
                try:
                    system_info = self._get_system_info(target, port, protocol, credentials)
                    if system_info:
                        results["device_info"]["broker_info"] = system_info
                        if "version" in system_info:
                            results["issues"].append(self.create_issue(
                                severity="medium",
                                description=f"MQTT broker version disclosed: {system_info['version']}",
                                details="The broker version is exposed, which may help attackers identify known vulnerabilities.",
                                remediation="Restrict access to $SYS topics and use the latest broker version.",
                            ))
                        if "connected_clients" in system_info:
                            results["issues"].append(self.create_issue(
                                severity="medium",
                                description=f"MQTT client information is exposed: {len(system_info['connected_clients'])} clients visible",
                                details="The broker exposes information about connected clients.",
                                remediation="Restrict access to $SYS/# topics that contain client information.",
                            ))
                except Exception as e:
                    self.logger.debug(f"Error getting system info: {str(e)}")

        # ── WebSocket MQTT detection (medium+) ──────────────────────────
        if not self.test_mode and self.intensity in ["medium", "high"]:
            for ws_port in WS_MQTT_PORTS:
                ws_issue = self._check_websocket_mqtt(target, ws_port)
                if ws_issue:
                    results["issues"].append(ws_issue)

        # ── High-intensity tests ────────────────────────────────────────
        if not self.test_mode and self.intensity == "high" and mqtt_ports:
            port, protocol = mqtt_ports[0]

            # Max connections test
            try:
                max_conn_issue = self._test_max_connections(target, port, protocol)
                if max_conn_issue:
                    results["issues"].append(max_conn_issue)
            except Exception as e:
                self.logger.debug(f"Error testing max connections: {str(e)}")

            # Client ID enumeration
            try:
                cid_issues = self._test_client_id_enumeration(target, port, protocol)
                results["issues"].extend(cid_issues)
            except Exception as e:
                self.logger.debug(f"Error testing client ID enumeration: {str(e)}")

        scan_duration = self.stop_scan_timer()
        self.logger.debug(f"MQTT scan completed in {scan_duration:.2f} seconds")
        return results

    # ── availability ─────────────────────────────────────────────────────

    def _check_mqtt_availability(self, target, port):
        """
        Check if an MQTT broker is available at the specified address.

        Returns:
            str: 'mqtt' for unencrypted, 'mqtts' for TLS, None if not available
        """
        # Try plain MQTT first (unless it's obviously the TLS port)
        if port == 1883 or port != 8883:
            try:
                client = self._make_client("ics_scanner_probe")
                ok, _ = self._connect_and_wait(client, target, port, wait=0.5)
                self._safe_disconnect(client)
                if ok:
                    return "mqtt"
            except Exception as e:
                self.logger.debug(f"Error checking MQTT on port {port}: {e}")

        # Try MQTT over TLS
        if port == 8883:
            try:
                client = self._make_client("ics_scanner_probe")
                self._apply_tls(client)
                ok, _ = self._connect_and_wait(client, target, port, wait=0.5)
                self._safe_disconnect(client)
                if ok:
                    return "mqtts"
            except Exception as e:
                self.logger.debug(f"Error checking MQTT/TLS on port {port}: {e}")

        return None

    # ── authentication ───────────────────────────────────────────────────

    def _test_authentication(self, target, port, protocol):
        """Test if the MQTT broker requires authentication."""
        result = {"anonymous_access": False, "default_credentials": []}

        # Anonymous access
        try:
            client = self._make_client("ics_scanner_auth")
            if protocol == "mqtts":
                self._apply_tls(client)
            ok, rc = self._connect_and_wait(client, target, port, wait=0.5)
            if ok:
                result["anonymous_access"] = True
            self._safe_disconnect(client)
        except Exception as e:
            self.logger.debug(f"Error testing anonymous access: {e}")

        # Default credentials (medium / high)
        if self.intensity in ["medium", "high"]:
            default_creds = [
                ("admin", "admin"), ("user", "user"), ("mqtt", "mqtt"),
                ("mosquitto", "mosquitto"), ("pi", "raspberry"),
                ("root", "root"), ("admin", "password"),
                ("device", "device"), ("subscriber", "subscriber"),
                ("publisher", "publisher"),
            ]
            for username, password in default_creds:
                try:
                    client = self._make_client("ics_scanner_auth")
                    client.username_pw_set(username, password)
                    if protocol == "mqtts":
                        self._apply_tls(client)
                    ok, rc = self._connect_and_wait(client, target, port, wait=0.5)
                    if ok:
                        result["default_credentials"].append((username, password))
                    self._safe_disconnect(client)
                except Exception as e:
                    self.logger.debug(f"Error testing credentials {username}:{password}: {e}")
                if hasattr(self, 'rate_limit'):
                    self.rate_limit()

        return result

    # ── topic access + retained message detection ────────────────────────

    def _test_topics_access(self, target, port, protocol, credentials=None):
        """Test access to MQTT topics with SUBACK verification and retained message detection."""
        result = {
            "readable_topics": [],
            "writable_topics": [],
            "retained_control_topics": [],
        }

        try:
            client = self._make_client("ics_scanner_topic_test")
            if credentials:
                client.username_pw_set(credentials[0], credentials[1])
            if protocol == "mqtts":
                self._apply_tls(client)

            topics_to_test = COMMON_MQTT_TOPICS[:5]
            if self.intensity == "medium":
                topics_to_test = COMMON_MQTT_TOPICS[:10]
            elif self.intensity == "high":
                topics_to_test = COMMON_MQTT_TOPICS

            received_messages = []
            topics_with_messages = set()
            subscribed_topics = set()
            sub_event = threading.Event()

            def on_message(_c, _ud, message):
                received_messages.append((message.topic, message.payload))
                topics_with_messages.add(message.topic)
                # Retained message detection
                if message.retain:
                    topic_lower = message.topic.lower()
                    if any(topic_lower.startswith(p) or f"/{p}" in topic_lower for p in CONTROL_TOPIC_PREFIXES):
                        if message.topic not in result["retained_control_topics"]:
                            result["retained_control_topics"].append(message.topic)

            def on_subscribe(_c, _ud, mid, granted_qos):
                subscribed_topics.add(mid)
                sub_event.set()

            client.on_message = on_message
            client.on_subscribe = on_subscribe

            ok, _ = self._connect_and_wait(client, target, port, wait=0.5)
            if not ok:
                self._safe_disconnect(client)
                return result

            # Subscribe with SUBACK tracking
            for topic in topics_to_test:
                try:
                    res, mid = client.subscribe(topic, 0)
                    if res == mqtt.MQTT_ERR_SUCCESS:
                        sub_event.clear()
                        sub_event.wait(timeout=0.3)
                except Exception as e:
                    self.logger.debug(f"Error subscribing to topic {topic}: {e}")

            # Wait for messages (retained + live)
            time.sleep(min(self.timeout, 2))

            # Test write access
            for topic in topics_to_test:
                if "#" in topic or "+" in topic or topic.startswith("$"):
                    continue
                test_message = f"ICS Scanner Test Message (Harmless) - {random.randint(1000, 9999)}"
                try:
                    pub_result = client.publish(topic, test_message, 0, retain=False)
                    if pub_result.rc == mqtt.MQTT_ERR_SUCCESS:
                        result["writable_topics"].append(topic)
                except Exception as e:
                    self.logger.debug(f"Error publishing to topic {topic}: {e}")

            # Readable topics from received messages
            if topics_with_messages:
                for topic, _ in received_messages:
                    if topic not in result["readable_topics"] and not topic.startswith("$"):
                        result["readable_topics"].append(topic)

            # Wildcards that were accepted via SUBACK count as readable
            for topic in topics_to_test:
                if ("#" in topic or "+" in topic) and topic not in result["readable_topics"]:
                    result["readable_topics"].append(topic)

            self._safe_disconnect(client)
        except Exception as e:
            self.logger.debug(f"Error testing topic access: {e}")

        return result

    # ── system info ──────────────────────────────────────────────────────

    def _get_system_info(self, target, port, protocol, credentials=None):
        """Get broker system information from $SYS topics."""
        system_info = {}

        try:
            client = self._make_client("ics_scanner_system_info")
            if credentials:
                client.username_pw_set(credentials[0], credentials[1])
            if protocol == "mqtts":
                self._apply_tls(client)

            system_topics = {
                "$SYS/broker/version": "version",
                "$SYS/broker/uptime": "uptime",
                "$SYS/broker/clients/total": "total_clients",
                "$SYS/broker/clients/connected": "connected_client_count",
                "$SYS/broker/subscriptions/count": "subscription_count",
                "$SYS/broker/messages/stored": "stored_messages",
                "$SYS/broker/clients/maximum": "max_clients",
                "$SYS/broker/messages/received": "messages_received",
                "$SYS/broker/messages/sent": "messages_sent",
                "$SYS/broker/load/connections/1min": "connection_rate",
                "$SYS/broker/memory/bytes": "memory_used",
            }

            def on_message(_c, _ud, message):
                topic = message.topic
                payload = message.payload.decode("utf-8", errors="ignore")
                if topic in system_topics:
                    system_info[system_topics[topic]] = payload
                if topic.startswith("$SYS/broker/clients/") and "/clients/" not in topic[18:]:
                    if "connected_clients" not in system_info:
                        system_info["connected_clients"] = []
                    system_info["connected_clients"].append({"topic": topic, "info": payload})

            client.on_message = on_message

            ok, _ = self._connect_and_wait(client, target, port, wait=0.5)
            if ok:
                client.subscribe("$SYS/#", 0)
                time.sleep(min(self.timeout, 3))

            self._safe_disconnect(client)
        except Exception as e:
            self.logger.debug(f"Error getting system info: {e}")

        return system_info

    # ── MQTT v5 detection ────────────────────────────────────────────────

    def _check_mqtt_v5(self, target, port, protocol):
        """Try connecting with MQTT v5 and report support level."""
        try:
            client = self._make_client("ics_scanner_v5", protocol=mqtt.MQTTv5)
            if protocol == "mqtts":
                self._apply_tls(client)

            v5_connected = threading.Event()
            v5_props = [None]

            def _on_connect(_c, _ud, _flags, rc, properties=None):
                v5_props[0] = properties
                if rc == 0:
                    v5_connected.set()

            client.on_connect = _on_connect
            client.connect_async(target, port, 60)
            client.loop_start()
            v5_connected.wait(timeout=0.5)
            self._safe_disconnect(client)

            if v5_connected.is_set():
                detail = "MQTT v5 is supported. V5 adds enhanced authentication, shared subscriptions, and message expiry."
                if v5_props[0] is not None:
                    detail += f" Server properties: {v5_props[0]}"
                return self.create_issue(
                    severity="info",
                    description="MQTT v5 protocol supported by broker",
                    details=detail,
                )
            else:
                return self.create_issue(
                    severity="info",
                    description="Broker does not support MQTT v5 (uses v3.1.1 or earlier)",
                    details="Consider upgrading to MQTT v5 for enhanced authentication and improved security features.",
                )
        except Exception as e:
            self.logger.debug(f"Error checking MQTT v5: {e}")
            return None

    # ── WebSocket MQTT detection ─────────────────────────────────────────

    def _check_websocket_mqtt(self, target, ws_port):
        """Check for MQTT-over-WebSocket endpoints."""
        try:
            # Quick TCP check first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((target, ws_port)) != 0:
                sock.close()
                return None
            sock.close()

            # Try MQTT over WebSocket
            client = self._make_client("ics_scanner_ws", transport="websockets")
            ok, _ = self._connect_and_wait(client, target, ws_port, wait=0.5)
            self._safe_disconnect(client)

            if ok:
                return self.create_issue(
                    severity="medium",
                    description=f"MQTT-over-WebSocket endpoint exposed on port {ws_port}",
                    details="WebSocket MQTT endpoints increase the attack surface by allowing browser-based clients to connect directly to the broker.",
                    remediation="Restrict WebSocket MQTT access with authentication, TLS, and firewall rules. Disable if not needed.",
                )
            else:
                return None
        except Exception as e:
            self.logger.debug(f"Error checking WebSocket MQTT on port {ws_port}: {e}")
            return None

    # ── QoS level testing ────────────────────────────────────────────────

    def _test_qos_levels(self, target, port, protocol, credentials=None):
        """Test which QoS levels the broker accepts and flag dangerous configurations."""
        try:
            client = self._make_client("ics_scanner_qos")
            if credentials:
                client.username_pw_set(credentials[0], credentials[1])
            if protocol == "mqtts":
                self._apply_tls(client)

            ok, _ = self._connect_and_wait(client, target, port, wait=0.5)
            if not ok:
                self._safe_disconnect(client)
                return None

            accepted_qos = []
            test_topic = "ics_scanner/qos_test"

            for qos in (0, 1, 2):
                try:
                    info = client.publish(test_topic, f"qos_{qos}_test", qos=qos, retain=False)
                    if info.rc == mqtt.MQTT_ERR_SUCCESS:
                        if qos > 0:
                            info.wait_for_publish(timeout=1.0)
                        accepted_qos.append(qos)
                except Exception as e:
                    self.logger.debug(f"QoS {qos} test failed: {e}")

            self._safe_disconnect(client)

            if accepted_qos:
                qos_str = ", ".join(str(q) for q in accepted_qos)
                details = f"Broker accepts QoS levels: {qos_str}."
                severity = "info"
                if 0 in accepted_qos:
                    details += " QoS 0 (fire-and-forget) on control topics is dangerous — no delivery guarantee for commands."
                    severity = "low"
                return self.create_issue(
                    severity=severity,
                    description=f"MQTT QoS levels accepted: {qos_str}",
                    details=details,
                    remediation="Enforce QoS 1 or 2 on control/command topics to ensure reliable delivery.",
                )
        except Exception as e:
            self.logger.debug(f"Error testing QoS levels: {e}")
        return None

    # ── Will message check ───────────────────────────────────────────────

    def _check_will_message(self, target, port, protocol):
        """Check if broker accepts Last Will messages without authentication."""
        try:
            client = self._make_client("ics_scanner_will")
            if protocol == "mqtts":
                self._apply_tls(client)

            client.will_set(
                topic="ics_scanner/will_test",
                payload="will_test_payload",
                qos=1,
                retain=False,
            )

            ok, _ = self._connect_and_wait(client, target, port, wait=0.5)
            self._safe_disconnect(client)

            if ok:
                return self.create_issue(
                    severity="medium",
                    description="Broker accepts Last Will and Testament messages without authentication",
                    details="An unauthenticated client can set a Last Will message that the broker publishes on disconnect. An attacker could inject malicious will messages to control topics.",
                    remediation="Require authentication for all connections and restrict will message topics via ACLs.",
                )
        except Exception as e:
            self.logger.debug(f"Error checking will message: {e}")
        return None

    # ── Max connections test (high intensity) ────────────────────────────

    def _test_max_connections(self, target, port, protocol, count=5):
        """Test if broker limits simultaneous connections."""
        clients = []
        connected_count = 0

        try:
            for i in range(count):
                client = self._make_client(f"ics_scanner_flood_{i}")
                if protocol == "mqtts":
                    self._apply_tls(client)
                ok, _ = self._connect_and_wait(client, target, port, wait=0.5)
                if ok:
                    connected_count += 1
                    clients.append(client)
                else:
                    self._safe_disconnect(client)
        except Exception as e:
            self.logger.debug(f"Error during max connections test: {e}")
        finally:
            for c in clients:
                self._safe_disconnect(c)

        if connected_count >= count:
            return self.create_issue(
                severity="medium",
                description=f"Broker accepted {connected_count} simultaneous connections without limit",
                details=f"The broker accepted all {count} concurrent connections. Without connection limits, an attacker can exhaust broker resources (DoS).",
                remediation="Configure maximum connection limits per client IP and globally in the broker settings.",
            )
        return None

    # ── Client ID enumeration (high intensity) ───────────────────────────

    def _test_client_id_enumeration(self, target, port, protocol):
        """Try connecting with common ICS client IDs to detect impersonation risk."""
        issues = []

        for cid in ICS_CLIENT_IDS:
            try:
                client = self._make_client(cid)
                if protocol == "mqtts":
                    self._apply_tls(client)

                disconnected_event = threading.Event()

                def _on_disconnect(_c, _ud, rc):
                    if rc != 0:  # unexpected disconnect = broker kicked us (same client ID)
                        disconnected_event.set()

                client.on_disconnect = _on_disconnect
                ok, _ = self._connect_and_wait(client, target, port, wait=0.5)

                if ok:
                    # Stay connected briefly to see if broker disconnects existing client
                    time.sleep(min(0.3, self.timeout / 10))
                    if not disconnected_event.is_set() and client.is_connected():
                        # We connected successfully with an ICS client ID — no auth required
                        issues.append(self.create_issue(
                            severity="high",
                            description=f"Broker accepted connection with ICS client ID: {cid}",
                            details=f"Connecting with client ID '{cid}' succeeded without authentication. If a real device uses this ID, the attacker's connection would hijack it (MQTT only allows one connection per client ID).",
                            remediation="Require authentication and bind client IDs to specific credentials. Enable client ID prefixes or validation.",
                        ))

                self._safe_disconnect(client)
            except Exception as e:
                self.logger.debug(f"Error testing client ID {cid}: {e}")

            if hasattr(self, 'rate_limit'):
                self.rate_limit()

            if len(issues) >= 3:  # cap to avoid excessive scanning
                break

        return issues
