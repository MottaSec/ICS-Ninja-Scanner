#!/usr/bin/env python3
"""
OPC-UA protocol scanner for detecting security issues in OPC-UA servers.

Developed by MottaSec Ghost Team - The unseen guardians of industrial systems.
"""

import socket
import time
import ssl
from datetime import datetime

from scanners.base_scanner import BaseScanner

try:
    from opcua import Client, ua
    from opcua.crypto import security_policies
    OPCUA_AVAILABLE = True
except ImportError:
    OPCUA_AVAILABLE = False


# Common default credentials for OPC-UA servers
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("user", "user"),
    ("user", "password"),
    ("opcua", "opcua"),
    ("operator", "operator"),
    ("guest", "guest"),
    ("root", "root"),
    ("administrator", "administrator"),
]

# Deprecated / weak security policies
WEAK_POLICIES = {
    "Basic128Rsa15": "medium",
    "Basic256": "medium",
}

# Security modes mapped to human-readable names
SECURITY_MODE_NAMES = {
    1: "None",
    2: "Sign",
    3: "SignAndEncrypt",
}


class OPCUAScanner(BaseScanner):
    """
    Scanner for detecting security issues in OPC-UA servers.

    Checks for insecure security modes, weak policies, anonymous access,
    default credentials, exposed node trees, and writable nodes.
    """

    def __init__(self, intensity='low', timeout=5, verify=True):
        """
        Initialize the OPC-UA scanner.

        Args:
            intensity (str): Scan intensity level ('low', 'medium', 'high')
            timeout (int): Connection timeout in seconds
            verify (bool): Whether to verify SSL/TLS certificates
        """
        super().__init__(intensity, timeout, verify)
        self.standard_ports = [4840]  # Standard OPC-UA port

    def scan(self, target, open_ports=None):
        """
        Scan a target for OPC-UA security issues.

        Args:
            target (str): Target IP address or hostname
            open_ports (list): List of open ports (optional)

        Returns:
            dict: Scan results or None if no OPC-UA server found
        """
        if not OPCUA_AVAILABLE:
            self.logger.error("python-opcua library is not installed. Cannot scan OPC-UA.")
            return None

        results = {
            'device_info': {},
            'issues': []
        }

        # Determine which ports to scan
        ports_to_scan = open_ports if open_ports else self.standard_ports

        # Check availability on each candidate port
        opcua_port = None
        for port in ports_to_scan:
            if self._check_opcua_availability(target, port):
                opcua_port = port
                break

        if not opcua_port:
            return None

        # --- Low intensity: detection and endpoint discovery ---
        results['device_info']['port'] = opcua_port
        results['issues'].append(self.create_issue(
            severity='info',
            description=f"OPC-UA Server Found: {target}:{opcua_port}",
            details="A device responding to the OPC-UA protocol was detected."
        ))

        # Discover endpoints (always done, needed by higher intensities too)
        endpoints = self._get_endpoints(target, opcua_port)

        if endpoints:
            # Extract server application info from first endpoint
            try:
                app_desc = endpoints[0].Server
                app_name = app_desc.ApplicationName.Text or "Unknown"
                product_uri = app_desc.ProductUri or "Unknown"
                app_uri = app_desc.ApplicationUri or "Unknown"

                results['device_info']['application_name'] = str(app_name)
                results['device_info']['product_uri'] = str(product_uri)
                results['device_info']['application_uri'] = str(app_uri)

                results['issues'].append(self.create_issue(
                    severity='info',
                    description=f"OPC-UA Server Identified: {app_name}",
                    details=(
                        f"Application Name: {app_name}\n"
                        f"Product URI: {product_uri}\n"
                        f"Application URI: {app_uri}"
                    )
                ))
            except Exception as e:
                self.logger.debug(f"Could not extract application info: {e}")

            # Report endpoint summary
            endpoint_details = []
            for ep in endpoints:
                mode_name = SECURITY_MODE_NAMES.get(ep.SecurityMode, str(ep.SecurityMode))
                policy = str(ep.SecurityPolicyUri).split("#")[-1] if ep.SecurityPolicyUri else "Unknown"
                endpoint_details.append(f"  - Mode: {mode_name}, Policy: {policy}, URL: {ep.EndpointUrl}")

            results['device_info']['endpoint_count'] = len(endpoints)
            results['issues'].append(self.create_issue(
                severity='info',
                description=f"OPC-UA Endpoint Discovery: {len(endpoints)} endpoint(s) found",
                details="\n".join(endpoint_details)
            ))
        else:
            results['issues'].append(self.create_issue(
                severity='info',
                description="Could not enumerate OPC-UA endpoints",
                details="Endpoint discovery failed; the server may restrict GetEndpoints."
            ))

        # --- Medium intensity: security analysis ---
        if self.intensity in ('medium', 'high') and endpoints:
            # Check security modes
            self._check_security_modes(endpoints, results)

            # Check security policies
            self._check_security_policies(endpoints, results)

            # Check certificate issues
            self._check_certificate_issues(endpoints, results)

            # Test anonymous authentication
            anon_client = self._test_anonymous_access(target, opcua_port)
            if anon_client is not None:
                results['device_info']['anonymous_access'] = True
                results['issues'].append(self.create_issue(
                    severity='high',
                    description="Anonymous authentication is allowed",
                    details="The OPC-UA server accepts connections without credentials.",
                    remediation=(
                        "Disable anonymous access in the server configuration. "
                        "Require username/password or certificate-based authentication."
                    )
                ))

                # Enumerate namespaces while we have a connection
                try:
                    ns_array = anon_client.get_namespace_array()
                    if ns_array:
                        results['device_info']['namespaces'] = ns_array
                        results['issues'].append(self.create_issue(
                            severity='info',
                            description=f"Server namespaces enumerated ({len(ns_array)} found)",
                            details="\n".join(f"  [{i}] {ns}" for i, ns in enumerate(ns_array))
                        ))
                except Exception as e:
                    self.logger.debug(f"Namespace enumeration failed: {e}")

                # Close the anonymous client
                try:
                    anon_client.disconnect()
                except Exception:
                    pass
            else:
                results['device_info']['anonymous_access'] = False

        # --- High intensity: active testing ---
        if self.intensity == 'high':
            # Test default credentials
            cred_result = self._test_default_credentials(target, opcua_port)
            if cred_result:
                username, _ = cred_result
                results['device_info']['default_credentials'] = True
                results['device_info']['weak_username'] = username
                results['issues'].append(self.create_issue(
                    severity='high',
                    description=f"Default credentials accepted (user: {username})",
                    details=(
                        "The server accepted a well-known default username/password combination. "
                        "An attacker could use these credentials for full access."
                    ),
                    remediation="Change default passwords immediately and enforce strong password policies."
                ))

            # Obtain a client for deeper testing (prefer anon, fallback to creds)
            test_client = self._get_test_client(target, opcua_port, cred_result)

            if test_client:
                try:
                    # Browse node tree
                    nodes_found = self._browse_node_tree(test_client)
                    if nodes_found:
                        results['device_info']['browsable_nodes'] = len(nodes_found)
                        sample = nodes_found[:15]
                        node_list = "\n".join(f"  - {n}" for n in sample)
                        if len(nodes_found) > 15:
                            node_list += f"\n  ... and {len(nodes_found) - 15} more"

                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description=f"Address space browsable: {len(nodes_found)} node(s) accessible",
                            details=f"Browsable nodes:\n{node_list}",
                            remediation="Restrict browse access through role-based access control."
                        ))

                    # Test write access
                    writable = self._test_write_access(test_client)
                    if writable:
                        results['device_info']['writable_nodes'] = len(writable)
                        writable_list = "\n".join(f"  - {n}" for n in writable[:10])
                        results['issues'].append(self.create_issue(
                            severity='critical',
                            description=f"Write access detected on {len(writable)} node(s)",
                            details=f"Writable nodes:\n{writable_list}",
                            remediation=(
                                "Restrict write permissions to authorized users only. "
                                "Implement role-based access control on the OPC-UA server."
                            )
                        ))

                    # Test method call access
                    self._check_method_access(test_client, results)

                    # Check diagnostics exposure
                    self._check_diagnostics_exposure(test_client, results)

                except Exception as e:
                    results['issues'].append(self.create_issue(
                        severity='info',
                        description=f"Error during active OPC-UA testing: {str(e)}",
                        details="The scanner encountered an error during deep inspection."
                    ))
                finally:
                    try:
                        test_client.disconnect()
                    except Exception:
                        pass

        return results

    # ------------------------------------------------------------------ #
    # Helper methods                                                      #
    # ------------------------------------------------------------------ #

    def _check_opcua_availability(self, target, port):
        """
        Check if an OPC-UA server is reachable on the given port.

        Performs a TCP connect followed by a lightweight OPC-UA Hello message.

        Args:
            target (str): Target IP address or hostname
            port (int): Port number

        Returns:
            bool: True if an OPC-UA service is detected
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((target, port))
            # OPC-UA Hello message (minimal)
            # MessageType: HEL (0x48454C), ChunkType: F (0x46)
            endpoint_url = f"opc.tcp://{target}:{port}".encode('utf-8')
            url_len = len(endpoint_url)
            # Header: 8 bytes + body (28 bytes fixed fields + url)
            body_len = 28 + url_len
            msg_size = 8 + body_len

            hello = bytearray()
            hello += b'HEL'  # MessageType
            hello += b'F'     # ChunkType (Final)
            hello += msg_size.to_bytes(4, 'little')  # MessageSize
            hello += (0).to_bytes(4, 'little')        # ProtocolVersion
            hello += (65536).to_bytes(4, 'little')    # ReceiveBufferSize
            hello += (65536).to_bytes(4, 'little')    # SendBufferSize
            hello += (0).to_bytes(4, 'little')        # MaxMessageSize
            hello += (0).to_bytes(4, 'little')        # MaxChunkCount
            hello += url_len.to_bytes(4, 'little')    # EndpointUrl length
            hello += endpoint_url                      # EndpointUrl

            sock.sendall(hello)
            response = sock.recv(1024)

            # Valid responses start with ACK (0x41434B) or ERR (0x455252)
            if len(response) >= 8:
                msg_type = response[:3]
                if msg_type in (b'ACK', b'ERR'):
                    return True

            return False
        except Exception:
            return False
        finally:
            sock.close()

    def _get_endpoints(self, target, port):
        """
        Discover OPC-UA endpoints on the target server.

        Args:
            target (str): Target IP address or hostname
            port (int): Port number

        Returns:
            list: List of endpoint descriptions, or empty list on failure
        """
        url = f"opc.tcp://{target}:{port}"
        client = Client(url, timeout=self.timeout)
        try:
            endpoints = client.connect_and_get_server_endpoints()
            return endpoints
        except Exception as e:
            self.logger.debug(f"Endpoint discovery failed: {e}")
            return []
        finally:
            try:
                client.disconnect()
            except Exception:
                pass

    def _check_security_modes(self, endpoints, results):
        """
        Analyse endpoint security modes and flag insecure ones.

        Args:
            endpoints (list): Endpoint descriptions
            results (dict): Results dict to append issues to
        """
        none_mode_found = False
        for ep in endpoints:
            if ep.SecurityMode == ua.MessageSecurityMode.None_:
                none_mode_found = True
                break

        if none_mode_found:
            results['issues'].append(self.create_issue(
                severity='critical',
                description="Endpoint with SecurityMode 'None' detected",
                details=(
                    "At least one endpoint accepts connections with no message security. "
                    "All communication on this endpoint is unencrypted and unsigned."
                ),
                remediation=(
                    "Disable endpoints with SecurityMode 'None'. "
                    "Require at minimum 'Sign', preferably 'SignAndEncrypt'."
                )
            ))

    def _check_security_policies(self, endpoints, results):
        """
        Check for deprecated or weak security policies on endpoints.

        Args:
            endpoints (list): Endpoint descriptions
            results (dict): Results dict to append issues to
        """
        flagged_policies = set()
        for ep in endpoints:
            policy_uri = str(ep.SecurityPolicyUri) if ep.SecurityPolicyUri else ""
            policy_name = policy_uri.split("#")[-1] if "#" in policy_uri else policy_uri

            if policy_name in WEAK_POLICIES and policy_name not in flagged_policies:
                flagged_policies.add(policy_name)
                severity = WEAK_POLICIES[policy_name]
                results['issues'].append(self.create_issue(
                    severity=severity,
                    description=f"Deprecated security policy in use: {policy_name}",
                    details=(
                        f"The policy '{policy_name}' is considered weak or deprecated. "
                        "It may be vulnerable to cryptographic attacks."
                    ),
                    remediation=(
                        "Migrate to stronger security policies such as Basic256Sha256 or Aes128_Sha256_RsaOaep. "
                        "Remove deprecated policies from the server configuration."
                    )
                ))

    def _check_certificate_issues(self, endpoints, results):
        """
        Inspect endpoint certificates for common issues (self-signed, expired).

        Args:
            endpoints (list): Endpoint descriptions
            results (dict): Results dict to append issues to
        """
        checked = False
        for ep in endpoints:
            if not ep.ServerCertificate:
                continue
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert = x509.load_der_x509_certificate(ep.ServerCertificate, default_backend())

                # Check self-signed
                if cert.issuer == cert.subject:
                    if not checked:
                        results['issues'].append(self.create_issue(
                            severity='medium',
                            description="Server uses a self-signed certificate",
                            details=f"Subject: {cert.subject.rfc4514_string()}",
                            remediation="Use certificates signed by a trusted CA for production systems."
                        ))
                        checked = True

                # Check expiry
                if cert.not_valid_after_utc < datetime.utcnow():
                    results['issues'].append(self.create_issue(
                        severity='medium',
                        description="Server certificate has expired",
                        details=f"Expired on: {cert.not_valid_after_utc.isoformat()}",
                        remediation="Renew the server certificate immediately."
                    ))
                    break  # One expiry notice is enough

            except ImportError:
                self.logger.debug("cryptography library not available; skipping cert checks")
                break
            except Exception as e:
                self.logger.debug(f"Certificate inspection error: {e}")
                break

    def _test_anonymous_access(self, target, port):
        """
        Attempt to connect to the OPC-UA server without credentials.

        Args:
            target (str): Target IP address or hostname
            port (int): Port number

        Returns:
            Client or None: Connected client if anonymous access works, else None
        """
        url = f"opc.tcp://{target}:{port}"
        client = Client(url, timeout=self.timeout)
        try:
            client.set_security_string("None,None,None")
        except Exception:
            pass  # Some versions don't support this method

        try:
            client.connect()
            # Quick sanity check — read the server status node
            client.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus)).get_value()
            return client
        except Exception:
            try:
                client.disconnect()
            except Exception:
                pass
            return None

    def _test_default_credentials(self, target, port):
        """
        Try common default username/password pairs against the server.

        Args:
            target (str): Target IP address or hostname
            port (int): Port number

        Returns:
            tuple or None: (username, password) if successful, else None
        """
        url = f"opc.tcp://{target}:{port}"

        for username, password in DEFAULT_CREDENTIALS:
            client = Client(url, timeout=self.timeout)
            client.set_user(username)
            client.set_password(password)
            try:
                client.connect()
                # Verify we actually have a session
                client.get_node(ua.NodeId(ua.ObjectIds.Server_ServerStatus)).get_value()
                client.disconnect()
                return (username, password)
            except Exception as e:
                self.logger.debug(f"Credential test {username} failed: {e}")
                try:
                    client.disconnect()
                except Exception:
                    pass
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        return None

    def _get_test_client(self, target, port, credentials=None):
        """
        Obtain a connected client for deep testing (anon or creds).

        Args:
            target (str): Target IP address or hostname
            port (int): Port number
            credentials (tuple or None): (username, password)

        Returns:
            Client or None: Connected client or None
        """
        url = f"opc.tcp://{target}:{port}"

        # Try anonymous first
        client = Client(url, timeout=self.timeout)
        try:
            client.connect()
            return client
        except Exception:
            try:
                client.disconnect()
            except Exception:
                pass

        # Try with credentials
        if credentials:
            username, password = credentials
            client = Client(url, timeout=self.timeout)
            client.set_user(username)
            client.set_password(password)
            try:
                client.connect()
                return client
            except Exception:
                try:
                    client.disconnect()
                except Exception:
                    pass

        return None

    def _browse_node_tree(self, client, max_depth=3, max_nodes=200):
        """
        Recursively browse the OPC-UA address space.

        Args:
            client (Client): Connected OPC-UA client
            max_depth (int): Maximum browse depth
            max_nodes (int): Maximum number of nodes to collect

        Returns:
            list: List of node display strings (NodeId — BrowseName)
        """
        found_nodes = []
        visited = set()

        def _browse(node, depth):
            if depth > max_depth or len(found_nodes) >= max_nodes:
                return
            try:
                children = node.get_children()
                for child in children:
                    node_id_str = str(child.nodeid)
                    if node_id_str in visited:
                        continue
                    visited.add(node_id_str)

                    try:
                        browse_name = child.get_browse_name().to_string()
                    except Exception:
                        browse_name = node_id_str

                    found_nodes.append(f"{node_id_str} ({browse_name})")
                    if len(found_nodes) >= max_nodes:
                        return
                    _browse(child, depth + 1)
            except Exception:
                pass

        try:
            root = client.get_root_node()
            _browse(root, 0)
        except Exception as e:
            self.logger.debug(f"Node tree browse error: {e}")

        return found_nodes

    def _test_write_access(self, client, max_tests=20):
        """
        Test if any variable nodes are writable. Reads the current value,
        writes a test value, then restores the original.

        Only tests nodes under the Objects folder to avoid server internals.

        Args:
            client (Client): Connected OPC-UA client
            max_tests (int): Maximum number of nodes to test

        Returns:
            list: List of writable node descriptions
        """
        writable_nodes = []
        tested = 0

        try:
            objects = client.get_objects_node()
            candidates = self._collect_variable_nodes(objects, max_count=max_tests * 3)
        except Exception:
            return writable_nodes

        for node in candidates:
            if tested >= max_tests:
                break
            try:
                # Read current value
                original_value = node.get_value()
                if original_value is None:
                    continue

                tested += 1

                # Determine a safe test value
                test_value = self._safe_test_value(original_value)
                if test_value is None:
                    continue

                # Attempt write
                node.set_value(ua.DataValue(ua.Variant(test_value, node.get_data_type_as_variant_type())))

                # Restore original
                node.set_value(ua.DataValue(ua.Variant(original_value, node.get_data_type_as_variant_type())))

                try:
                    browse_name = node.get_browse_name().to_string()
                except Exception:
                    browse_name = str(node.nodeid)

                writable_nodes.append(f"{node.nodeid} ({browse_name})")

            except Exception:
                # Write failed — that's expected for read-only nodes
                pass
            if hasattr(self, 'rate_limit'):
                self.rate_limit()

        return writable_nodes

    def _collect_variable_nodes(self, parent_node, max_count=60, depth=0, max_depth=3):
        """
        Collect variable-type child nodes for write testing.

        Args:
            parent_node: OPC-UA node to start from
            max_count (int): Max nodes to collect
            depth (int): Current recursion depth
            max_depth (int): Maximum recursion depth

        Returns:
            list: List of variable nodes
        """
        variables = []
        if depth > max_depth or len(variables) >= max_count:
            return variables

        try:
            children = parent_node.get_children()
            for child in children:
                if len(variables) >= max_count:
                    break
                try:
                    node_class = child.get_node_class()
                    if node_class == ua.NodeClass.Variable:
                        variables.append(child)
                    elif node_class == ua.NodeClass.Object:
                        variables.extend(
                            self._collect_variable_nodes(child, max_count - len(variables), depth + 1, max_depth)
                        )
                except Exception:
                    pass
        except Exception:
            pass

        return variables

    @staticmethod
    def _safe_test_value(original):
        """
        Generate a minimally-different test value for safe write testing.

        Args:
            original: The original value read from the node

        Returns:
            Modified value or None if type is not supported
        """
        if isinstance(original, bool):
            return not original
        if isinstance(original, int):
            return original + 1 if original < 2**31 - 1 else original - 1
        if isinstance(original, float):
            return original + 0.001
        if isinstance(original, str):
            return original + "_test"
        return None

    def _check_method_access(self, client, results):
        """
        Check if OPC-UA methods are callable without authorization.

        Args:
            client (Client): Connected OPC-UA client
            results (dict): Results dict to append issues to
        """
        methods_found = []
        try:
            objects = client.get_objects_node()
            children = objects.get_children()
            for child in children[:30]:  # Limit scope
                try:
                    refs = child.get_references(ua.ObjectIds.HasComponent)
                    for ref in refs:
                        try:
                            method_node = client.get_node(ref.NodeId)
                            if method_node.get_node_class() == ua.NodeClass.Method:
                                browse_name = method_node.get_browse_name().to_string()
                                methods_found.append(f"{ref.NodeId} ({browse_name})")
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception as e:
            self.logger.debug(f"Method access check error: {e}")

        if methods_found:
            method_list = "\n".join(f"  - {m}" for m in methods_found[:10])
            if len(methods_found) > 10:
                method_list += f"\n  ... and {len(methods_found) - 10} more"

            results['device_info']['exposed_methods'] = len(methods_found)
            results['issues'].append(self.create_issue(
                severity='medium',
                description=f"OPC-UA methods exposed: {len(methods_found)} method(s) discoverable",
                details=f"Discoverable methods:\n{method_list}",
                remediation="Restrict method visibility and invocation to authorized sessions only."
            ))

    def _check_diagnostics_exposure(self, client, results):
        """
        Check if server diagnostics nodes are readable (SessionDiagnostics,
        ServerDiagnostics).

        Args:
            client (Client): Connected OPC-UA client
            results (dict): Results dict to append issues to
        """
        diagnostic_nodes = [
            (ua.ObjectIds.Server_ServerDiagnostics, "ServerDiagnostics"),
            (ua.ObjectIds.Server_ServerDiagnostics_SessionsDiagnosticsSummary, "SessionsDiagnosticsSummary"),
            (ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary, "ServerDiagnosticsSummary"),
        ]

        exposed = []
        for node_id, name in diagnostic_nodes:
            try:
                node = client.get_node(ua.NodeId(node_id))
                children = node.get_children()
                if children:
                    exposed.append(name)
            except Exception as e:
                self.logger.debug(f"Diagnostics node {name} check failed: {e}")

        if exposed:
            results['device_info']['diagnostics_exposed'] = exposed
            results['issues'].append(self.create_issue(
                severity='medium',
                description=f"Server diagnostics information exposed: {', '.join(exposed)}",
                details=(
                    "Diagnostic nodes reveal operational details such as active sessions, "
                    "subscription counts, and server health — useful for attacker reconnaissance."
                ),
                remediation="Restrict read access to diagnostics nodes to administrator roles only."
            ))
