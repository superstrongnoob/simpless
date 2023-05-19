import socket

__all__ = ['ss_parse_addr']


S5_AUTH_NONE        = 1
S5_AUTH_GSSAPI      = 2
S5_AUTH_PASSWD      = 4


class S5Parser:
    def __init__(self):
        self.state = "s5_version"
        self.arg0 = 0
        self.arg1 = 0
        self.methods = 0
        self.username = ""
        self.userlen = 0
        self.password = ""
        self.passlen = 0
        self.cmd = ""
        self.atyp = ""
        self.daddr = b""
        self.dport = 0
        self.last_err = ""

    def parse_ss(self, data: bytes) -> int:
        if len(data) < 7:
            return "s5_bad_prot"

        self.state = "s5_req_atyp"
        return self.parse(data)

    def parse(self, data: bytes) -> int:
        err = "s5_ok"
        i = 0
        n = len(data)

        while i < n:
            c = data[i]
            i += 1

            if self.state == "s5_version":
                if c != 5:
                    err = "s5_bad_version"
                    break
                self.state = "s5_nmethods"

            elif self.state == "s5_nmethods":
                self.arg0 = 0
                self.arg1 = c
                self.state = "s5_methods"

            elif self.state == "s5_methods":
                if self.arg0 < self.arg1:
                    if c == 0:
                        self.methods |= S5_AUTH_NONE
                    elif c == 1:
                        self.methods |= S5_AUTH_GSSAPI
                    elif c == 2:
                        self.methods |= S5_AUTH_PASSWD
                    else:
                        pass  # Ignore everything we don't understand
                    self.arg0 += 1
                if self.arg0 == self.arg1:
                    err = "s5_auth_select"
                    break

            elif self.state == "s5_auth_pw_version":
                if c != 1:
                    err = "s5_bad_version"
                    break
                self.state = "s5_auth_pw_userlen"

            elif self.state == "s5_auth_pw_userlen":
                self.arg0 = 0
                self.userlen = c
                self.state = "s5_auth_pw_username"

            elif self.state == "s5_auth_pw_username":
                if self.arg0 < self.userlen:
                    self.username += chr(c)
                    self.arg0 += 1
                if self.arg0 == self.userlen:
                    self.state = "s5_auth_pw_passlen"

            elif self.state == "s5_auth_pw_passlen":
                self.arg0 = 0
                self.passlen = c
                self.state = "s5_auth_pw_password"

            elif self.state == "s5_auth_pw_password":
                if self.arg0 < self.passlen:
                    self.password += chr(c)
                    self.arg0 += 1
                if self.arg0 == self.passlen:
                    self.state = "s5_req_version"
                    err = "s5_auth_verify"
                    break

            elif self.state == "s5_req_version":
                if c != 5:
                    err = "s5_bad_version"
                    break
                self.state = "s5_req_cmd"

            elif self.state == "s5_req_cmd":
                if c == 1:
                    self.cmd = "s5_cmd_tcp_connect"
                elif c == 3:
                    self.cmd = "s5_cmd_udp_assoc"
                else:
                    err = "s5_bad_cmd"
                    break
                self.state = "s5_req_reserved"

            elif self.state == "s5_req_reserved":
                self.state = "s5_req_atyp"

            elif self.state == "s5_req_atyp":
                self.arg0 = 0
                if c == 1:
                    self.state = "s5_req_daddr"
                    self.atyp = "s5_atyp_ipv4"
                    self.arg1 = 4
                elif c == 3:
                    self.state = "s5_req_atyp_host"
                    self.atyp = "s5_atyp_host"
                    self.arg1 = 0
                elif c == 4:
                    self.state = "s5_req_daddr"
                    self.atyp = "s5_atyp_ipv6"
                    self.arg1 = 16
                else:
                    err = "s5_bad_atyp"
                    break

            elif self.state == "s5_req_atyp_host":
                self.arg1 = c
                self.state = "s5_req_daddr"

            elif self.state == "s5_req_daddr":
                if self.arg0 < self.arg1:
                    self.daddr += c.to_bytes(1, 'big')
                    self.arg0 += 1
                if self.arg0 == self.arg1:
                    self.state = "s5_req_dport0"

            elif self.state == "s5_req_dport0":
                self.dport = c << 8
                self.state = "s5_req_dport1"

            elif self.state == "s5_req_dport1":
                self.dport |= c
                self.state = "s5_dead"
                err = "s5_exec_cmd"
                break

            elif self.state == "s5_dead":
                break

            else:
                pass  # Unknown state

        self.last_err = err
        return i



def ss_parse_addr(data: bytes) -> tuple[int, tuple[str, int]]:
    parser = S5Parser()
    hdr_len = parser.parse_ss(data)
    if parser.last_err != "s5_exec_cmd":
        return (0, ('', 0))

    domain = ''
    port = parser.dport
    if parser.atyp == "s5_atyp_ipv4":
        domain = socket.inet_ntop(socket.AF_INET,parser.daddr)
    if parser.atyp == "s5_atyp_ipv6":
        domain = socket.inet_ntop(socket.AF_INET6, parser.daddr)
    if parser.atyp == "s5_atyp_host":
        domain = parser.daddr.decode()

    return (hdr_len, (domain, port))
