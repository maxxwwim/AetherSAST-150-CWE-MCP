use crate::linter::{CveRuleDef, LinterViolation};

/// Règles de sécurité natives C / C++ & FFI / Réseau bas-niveau.
pub struct CppSecurityRules;

impl CppSecurityRules {
    pub fn definitions() -> Vec<CveRuleDef> {
        vec![
            CveRuleDef {
                rule_id: "CVE-CPP-UNBOUNDED-COPY-UAF".to_string(),
                cve_id: "CWE-120 / BUFFER-OVERFLOW-FFI".to_string(),
                name: "Débordement de Tampon Mémoire C/C++ (strcpy / sprintf / memcpy non borné)".to_string(),
                category: "C / C++ / FFI".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Utilisation de primitives C/C++ sans contrôle de taille (strcpy, strcat, sprintf, gets, memcpy non borné) exposant la pile ou le tas à une corruption mémoire critique.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-INTEGER-OVERFLOW-ALLOC".to_string(),
                cve_id: "CWE-190 / INTEGER-OVERFLOW-ALLOC-OOM".to_string(),
                name: "Dépassement d'Entier sur Calcul de Longueur Réseau & Allocation Tronquée".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Calcul arithmétique sur la taille d'un paquet réseau (+ sizeof(Header), * count) directement dans new char[] ou malloc() sans validation de dépassement (UINT32_MAX) : allocation tronquée puis heap overflow catastrophique.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-TYPE-PUNNING-STRICT-ALIASING".to_string(),
                cve_id: "CWE-843 / STRICT-ALIASING-TYPE-PUNNING".to_string(),
                name: "Type Punning Réseau par Cast de Pointeur Brut (Strict Aliasing UB)".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "HIGH".to_string(),
                description: "Cast direct d'un tampon d'octets brut (char*/uint8_t*) vers une structure de protocole (reinterpret_cast<Header*> ou (PacketHeader*)buf) : violation du Strict Aliasing (optimisations destructrices du compilateur) et risque de SIGBUS sur architectures à alignement strict.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-ASYNC-CALLBACK-UAF".to_string(),
                cve_id: "CWE-416 / ASYNC-EVENT-CALLBACK-UAF".to_string(),
                name: "Use-After-Free par Capture de this dans Callback Réseau Asynchrone".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Capture du pointeur brut [this] ou [&] dans un callback asynchrone (async_read, async_write, async_receive, uv_queue_work) sans shared_from_this() ni weak_ptr : si le socket/client est détruit avant la fin de l'I/O, l'appel ultérieur du handler accède à un objet libéré (UAF).".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-PARTIAL-READ-SHORT-FRAME".to_string(),
                cve_id: "CWE-252 / UNCHECKED-SHORT-STREAM-READ".to_string(),
                name: "Désynchronisation TCP par Lecture Partielle Non Bouclée (Unchecked Short Read)".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "HIGH".to_string(),
                description: "Appel unique à recv(), read() ou SSL_read() supposant la réception atomique de la trame complète sans boucle de cadrage ni validation stricte de taille : fragmentation TCP injectant des trames tronquées ou corrompues.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-SOCKET-FD-LEAK-EXCEPTION".to_string(),
                cve_id: "CWE-775 / SOCKET-FD-LEAK-EXCEPTION".to_string(),
                name: "Fuite de Descripteur Socket Réseau par Absence de RAII (FD Exhaustion DoS)".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "HIGH".to_string(),
                description: "Création d'un descripteur brut (socket(), accept(), open()) stocké dans un int sans garde RAII dans une fonction contenant des allocations dynamiques ou des exceptions (throw, new, std::string) : fuite cumulative de sockets et déni de service (EMFILE).".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-HOST-BYTE-ORDER-CONFUSION".to_string(),
                cve_id: "CWE-1385 / MISSING-ENDIANNESS-CONVERSION".to_string(),
                name: "Confusion d'Endianness sur Champ Longueur Réseau (Missing ntohs/ntohl)".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "HIGH".to_string(),
                description: "Lecture directe d'un champ de longueur réseau (header.length, pkt->size) dans des opérations de comparaison de bornes ou d'allocation sans conversion préalable par ntohs() / ntohl() : inversion d'octets contournant les gardes de sécurité sur processeurs Little-Endian.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-STRING-NULL-TERMINATION-OFF-BY-ONE".to_string(),
                cve_id: "CWE-170 / MISSING-NULL-TERMINATION-LEAK".to_string(),
                name: "Absence de Null-Termination sur Chaîne Réseau Reçue (Memory Bleed)".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Lecture réseau dans un buffer char[] sans forcer le byte nul terminal (buf[n] = '\\0'), suivi d'un traitement par strlen(), std::string(buf) ou printf(%s) : fuite d'informations adjacentes de la pile ou du heap (Heartbleed-like) et crash SIGSEGV.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-FORMAT-STRING-LOGGING".to_string(),
                cve_id: "CWE-134 / UNCONTROLLED-FORMAT-STRING-NET".to_string(),
                name: "Injection de Chaîne de Formatage sur Données Réseau (Format String RCE)".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Passage direct d'un buffer ou message reçu du réseau comme chaîne de format à syslog(), printf(), sprintf() ou fprintf() sans format spécifié (\"%s\") : lecture/écriture arbitraire en mémoire via les spécificateurs %x et %n (RCE).".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-SOCKET-RACE-DOUBLE-CLOSE".to_string(),
                cve_id: "CWE-415 / SOCKET-FD-RACE-DOUBLE-CLOSE".to_string(),
                name: "Double-Close & Race Condition sur Socket Multi-Thread (FD Re-use Hijack)".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "HIGH".to_string(),
                description: "Fermeture de socket close(fd) ou closesocket(fd) dans un destructeur ou gestionnaire d'événement sans réinitialisation atomique (exchange(-1)) ni verrou de synchronisation : fermetures concurrentes fermant par erreur les nouveaux sockets réalloués par l'OS.".to_string(),
                default_enabled: true,
            },
            CveRuleDef {
                rule_id: "CVE-CPP-NET-UNBOUNDED-RECURSION-TLV-PARSER".to_string(),
                cve_id: "CWE-674 / UNBOUNDED-RECURSIVE-NET-PARSER".to_string(),
                name: "Récursion Non Bornée sur Parseur de Protocole Réseau (Stack Exhaustion Crash)".to_string(),
                category: "C / C++ / Network".to_string(),
                severity: "HIGH".to_string(),
                description: "Fonction de parsing récursif de paquets réseau imbriqués (TLV, JSON, BSON, expressions) s'appelant récursivement sans compteur ni plafond de profondeur (depth > MAX_DEPTH) : trame malveillante hautement imbriquée provoquant un Stack Overflow immédiat (SIGSEGV).".to_string(),
                default_enabled: true,
            },
        ]
    }

    pub fn audit_line<F>(
        file_path: &str,
        line_no: usize,
        trimmed: &str,
        content_contains: F,
        violations: &mut Vec<LinterViolation>,
    ) where
        F: Fn(&'static str) -> bool,
    {
        // CVE-CPP-UNBOUNDED-COPY-UAF (CWE-120 / Classic Buffer Overflow in Native C/C++)
        if trimmed.contains("strcpy(")
            || trimmed.contains("strcat(")
            || trimmed.contains("sprintf(")
            || trimmed.contains("gets(")
            || (trimmed.contains("memcpy(") && !content_contains("sizeof(") && !content_contains("MAX_"))
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-UNBOUNDED-COPY-UAF".to_string(),
                cve_id: "CWE-120 / BUFFER-OVERFLOW-FFI".to_string(),
                severity: "CRITICAL".to_string(),
                message: "Unbounded memory copy (strcpy/strcat/sprintf/gets/memcpy) in native C/C++ module leads to stack/heap buffer overflow and RCE".to_string(),
                transmitted_data: Some("raw_c_buffer_pointer".to_string()),
                transmitted_type: Some("char* / void* (Unbounded Memory Copy)".to_string()),
                remediation: "Replace with bounds-checked snprintf(buf, sizeof(buf), ...), strncpy_s, or std::string / std::span.".to_string(),
            });
        }

        // 1. CVE-CPP-NET-INTEGER-OVERFLOW-ALLOC (CWE-190 / CWE-789)
        if (trimmed.contains("new char[")
            || trimmed.contains("new uint8_t[")
            || trimmed.contains("malloc(")
            || trimmed.contains("realloc("))
            && (trimmed.contains(" + sizeof(")
                || trimmed.contains(" + header_len")
                || trimmed.contains(" + hdr_len")
                || trimmed.contains(" + sizeof_header")
                || trimmed.contains("len + ")
                || trimmed.contains("size + ")
                || trimmed.contains("length + ")
                || trimmed.contains("payload_len +"))
            && !content_contains("__builtin_add_overflow")
            && !content_contains("std::numeric_limits")
            && !content_contains("MAX_PACKET")
            && !content_contains("MAX_SIZE")
            && !content_contains("check_overflow")
            && !content_contains("safe_add")
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-INTEGER-OVERFLOW-ALLOC".to_string(),
                cve_id: "CWE-190 / INTEGER-OVERFLOW-ALLOC-OOM".to_string(),
                severity: "CRITICAL".to_string(),
                message: "Integer overflow in network frame length calculation (+ sizeof / + len) inside memory allocation without overflow guard: UINT32_MAX wrap-around leads to undersized buffer and heap corruption".to_string(),
                transmitted_data: Some("packet_allocation_size".to_string()),
                transmitted_type: Some("size_t / uint32_t (Integer Overflow Allocation)".to_string()),
                remediation: "Validate bounds against MAX_PACKET_SIZE - sizeof(Header) or use __builtin_add_overflow before allocating memory.".to_string(),
            });
        }

        // 2. CVE-CPP-NET-TYPE-PUNNING-STRICT-ALIASING (CWE-843 / CWE-704)
        if ((trimmed.contains("reinterpret_cast<")
            && (trimmed.contains("Header*")
                || trimmed.contains("Packet*")
                || trimmed.contains("Message*")
                || trimmed.contains("Frame*")
                || trimmed.contains("Msg*")))
            || ((trimmed.contains("(Header*)")
                || trimmed.contains("(Packet*)")
                || trimmed.contains("(PacketHeader*)"))
                && !trimmed.contains("malloc")
                && !trimmed.contains("new ")))
            && !content_contains("std::memcpy")
            && !content_contains("bit_cast")
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-TYPE-PUNNING-STRICT-ALIASING".to_string(),
                cve_id: "CWE-843 / STRICT-ALIASING-TYPE-PUNNING".to_string(),
                severity: "HIGH".to_string(),
                message: "Type punning raw network byte stream to protocol struct pointer via reinterpret_cast violates C++ strict aliasing rules and causes unaligned SIGBUS crashes or compiler reordering UB".to_string(),
                transmitted_data: Some("misaligned_protocol_struct_ptr".to_string()),
                transmitted_type: Some("T* (Strict Aliasing UB)".to_string()),
                remediation: "Copy protocol headers into properly aligned structs with std::memcpy(&hdr, buf, sizeof(hdr)) or use C++20 std::bit_cast.".to_string(),
            });
        }

        // 3. CVE-CPP-NET-ASYNC-CALLBACK-UAF (CWE-416 / CWE-824)
        if (trimmed.contains("async_read")
            || trimmed.contains("async_write")
            || trimmed.contains("async_receive")
            || trimmed.contains("async_send")
            || trimmed.contains("async_wait")
            || trimmed.contains("async_accept")
            || trimmed.contains("uv_queue_work"))
            && (trimmed.contains("[this]")
                || trimmed.contains("[&]")
                || trimmed.contains("[this,")
                || trimmed.contains("[=]"))
            && !content_contains("shared_from_this")
            && !content_contains("weak_from_this")
            && !content_contains("enable_shared_from_this")
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-ASYNC-CALLBACK-UAF".to_string(),
                cve_id: "CWE-416 / ASYNC-EVENT-CALLBACK-UAF".to_string(),
                severity: "CRITICAL".to_string(),
                message: "Capturing raw 'this' or [&] inside asynchronous I/O completion callback (Boost.Asio/libuv) without shared_from_this(): session destruction while I/O is pending triggers Use-After-Free".to_string(),
                transmitted_data: Some("dangling_this_pointer".to_string()),
                transmitted_type: Some("this* (Use-After-Free in Async Handler)".to_string()),
                remediation: "Inherit from std::enable_shared_from_this and capture auto self = shared_from_this() or weak_from_this() in async completion handlers.".to_string(),
            });
        }

        // 4. CVE-CPP-NET-PARTIAL-READ-SHORT-FRAME (CWE-252 / CWE-670)
        if (trimmed.contains("recv(")
            || trimmed.contains("read(")
            || trimmed.contains("SSL_read("))
            && !trimmed.contains("async_read")
            && !trimmed.contains("read_some")
            && !trimmed.contains("read_exact")
            && (trimmed.contains("buf") || trimmed.contains("buffer") || trimmed.contains("packet"))
            && !content_contains("while")
            && !content_contains("for (")
            && !content_contains("read_exact")
            && !content_contains("boost::asio::read")
            && !content_contains("bytes_transferred == ")
            && !content_contains("total_read += ")
            && !content_contains("received_bytes >= ")
            && !content_contains("n < sizeof(")
            && !content_contains("ret != sizeof(")
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-PARTIAL-READ-SHORT-FRAME".to_string(),
                cve_id: "CWE-252 / UNCHECKED-SHORT-STREAM-READ".to_string(),
                severity: "HIGH".to_string(),
                message: "Unchecked single socket read (recv/read/SSL_read) assuming complete atomic frame arrival on TCP byte stream: packet fragmentation leads to desync and uninitialized memory consumption".to_string(),
                transmitted_data: Some("partial_network_stream_frame".to_string()),
                transmitted_type: Some("ssize_t (Short Read Desync)".to_string()),
                remediation: "Loop until all expected frame bytes are accumulated (while (total < expected)) or use framed framing helpers like boost::asio::read.".to_string(),
            });
        }

        // 5. CVE-CPP-NET-SOCKET-FD-LEAK-EXCEPTION (CWE-775 / CWE-403)
        if (trimmed.contains("int sock = socket(")
            || trimmed.contains("int fd = socket(")
            || trimmed.contains("int client = accept(")
            || trimmed.contains("int client_fd = accept("))
            && content_contains("throw ")
            && !content_contains("unique_fd")
            && !content_contains("SocketGuard")
            && !content_contains("unique_ptr")
            && !content_contains("RAII")
            && !content_contains("close(sock)")
            && !content_contains("close(fd)")
            && !content_contains("close(client)")
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-SOCKET-FD-LEAK-EXCEPTION".to_string(),
                cve_id: "CWE-775 / SOCKET-FD-LEAK-EXCEPTION".to_string(),
                severity: "HIGH".to_string(),
                message: "Raw socket descriptor allocated without RAII wrapper in function with throw/exception paths: unhandled error leaks socket file descriptors, resulting in EMFILE exhaustion DoS".to_string(),
                transmitted_data: Some("unmanaged_socket_descriptor".to_string()),
                transmitted_type: Some("int (Raw Socket Handle Leak)".to_string()),
                remediation: "Wrap socket file descriptors in an RAII guard (struct SocketGuard { ~SocketGuard() { if (fd >= 0) close(fd); } };) or std::unique_ptr with custom deleter.".to_string(),
            });
        }

        // 6. CVE-CPP-NET-HOST-BYTE-ORDER-CONFUSION (CWE-1385 / CWE-681)
        if (trimmed.contains("header.length")
            || trimmed.contains("header.payload_len")
            || trimmed.contains("pkt->length")
            || trimmed.contains("pkt->size")
            || trimmed.contains("msg->len"))
            && (trimmed.contains("< ") || trimmed.contains("> ") || trimmed.contains("new ") || trimmed.contains("malloc(") || trimmed.contains("buffer["))
            && !content_contains("ntohs(")
            && !content_contains("ntohl(")
            && !content_contains("be16toh(")
            && !content_contains("be32toh(")
            && !content_contains("std::byteswap")
            && !content_contains("endian::network_to_host")
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-HOST-BYTE-ORDER-CONFUSION".to_string(),
                cve_id: "CWE-1385 / MISSING-ENDIANNESS-CONVERSION".to_string(),
                severity: "HIGH".to_string(),
                message: "Accessing multi-byte network packet length/offset without host byte order conversion (ntohs/ntohl/byteswap): big-endian network wire bytes evaluated on little-endian host bypasses bounds validation".to_string(),
                transmitted_data: Some("unconverted_network_endianness".to_string()),
                transmitted_type: Some("uint16_t / uint32_t (Host/Network Endian Mismatch)".to_string()),
                remediation: "Convert all multi-byte wire fields with ntohs() (16-bit) or ntohl() (32-bit) before performing bounds checks or allocations.".to_string(),
            });
        }

        // 7. CVE-CPP-NET-STRING-NULL-TERMINATION-OFF-BY-ONE (CWE-170 / CWE-193)
        if (trimmed.contains("recv(")
            || trimmed.contains("recvfrom(")
            || trimmed.contains("read("))
            && (content_contains("strlen(buf")
                || content_contains("strlen(buffer")
                || content_contains("std::string(buf")
                || content_contains("std::string(buffer")
                || content_contains("strcmp(buf")
                || content_contains("strcpy("))
            && !content_contains("= '\\0'")
            && !content_contains("= 0;")
            && !content_contains("std::string_view")
            && !content_contains("buf[bytes_read] =")
            && !content_contains("buffer[n] =")
            && !content_contains("buffer[len] =")
            && !content_contains("buf[n] =")
            && !content_contains("buf[ret] =")
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-STRING-NULL-TERMINATION-OFF-BY-ONE".to_string(),
                cve_id: "CWE-170 / MISSING-NULL-TERMINATION-LEAK".to_string(),
                severity: "CRITICAL".to_string(),
                message: "Network payload read into char buffer without explicit null termination before passing to strlen/std::string: memory disclosure bleed of adjacent stack/heap secrets (Heartbleed-like)".to_string(),
                transmitted_data: Some("unterminated_network_string_buffer".to_string()),
                transmitted_type: Some("char* (Improper Null Termination)".to_string()),
                remediation: "Ensure the buffer has capacity for null byte and explicitly set buf[bytes_received] = '\\0' or construct std::string with explicit length std::string(buf, bytes_received).".to_string(),
            });
        }

        // 8. CVE-CPP-NET-FORMAT-STRING-LOGGING (CWE-134)
        let is_format_string_vuln = ((trimmed.starts_with("syslog(") || trimmed.contains(" syslog("))
            && !trimmed.contains("syslog(LOG_")
            && !trimmed.contains("\""))
            || ((trimmed.starts_with("printf(") || trimmed.contains(" printf("))
                && !trimmed.contains("printf(\""))
            || ((trimmed.starts_with("fprintf(stderr,") || trimmed.contains("fprintf(stderr, "))
                && !trimmed.contains("fprintf(stderr, \"")
                && !trimmed.contains("fprintf(stderr, \"%s\""))
            || (trimmed.contains("syslog(LOG_ERR, ") && !trimmed.contains("syslog(LOG_ERR, \""))
            || (trimmed.contains("syslog(LOG_INFO, ") && !trimmed.contains("syslog(LOG_INFO, \""))
            || (trimmed.contains("syslog(LOG_WARNING, ") && !trimmed.contains("syslog(LOG_WARNING, \""));
        if is_format_string_vuln {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-FORMAT-STRING-LOGGING".to_string(),
                cve_id: "CWE-134 / UNCONTROLLED-FORMAT-STRING-NET".to_string(),
                severity: "CRITICAL".to_string(),
                message: "Uncontrolled format string: passing dynamic network payload/message directly to printf/syslog/fprintf allows %n arbitrary memory writes and %x memory disclosures (RCE)".to_string(),
                transmitted_data: Some("format_string_untrusted_specifier".to_string()),
                transmitted_type: Some("char* (Uncontrolled Format String)".to_string()),
                remediation: "Always provide a static string format literal: printf(\"%s\", msg) or syslog(LOG_ERR, \"%s\", msg.c_str()).".to_string(),
            });
        }

        // 9. CVE-CPP-NET-SOCKET-RACE-DOUBLE-CLOSE (CWE-415 / CWE-362)
        if (trimmed.contains("close(this->sock")
            || trimmed.contains("close(this->fd")
            || trimmed.contains("close(m_socket")
            || trimmed.contains("close(m_fd")
            || trimmed.contains("closesocket(this->")
            || trimmed.contains("closesocket(m_"))
            && !content_contains("std::atomic<int>")
            && !content_contains("std::mutex")
            && !content_contains("std::lock_guard")
            && !content_contains("exchange(-1)")
            && !content_contains("Atomic")
            && !content_contains("lock()")
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-SOCKET-RACE-DOUBLE-CLOSE".to_string(),
                cve_id: "CWE-415 / SOCKET-FD-RACE-DOUBLE-CLOSE".to_string(),
                severity: "HIGH".to_string(),
                message: "Closing member socket descriptor close(fd) without atomic exchange or mutex lock in multi-threaded connection context: race condition can close reallocated fd belonging to another connection".to_string(),
                transmitted_data: Some("unlocked_socket_descriptor".to_string()),
                transmitted_type: Some("int / SOCKET (Race Condition Double Close)".to_string()),
                remediation: "Use std::atomic<int> with exchange(-1) before closing (int old = fd.exchange(-1); if (old >= 0) close(old);) or protect close under a std::lock_guard.".to_string(),
            });
        }

        // 10. CVE-CPP-NET-UNBOUNDED-RECURSION-TLV-PARSER (CWE-674)
        if (trimmed.contains("parse_tlv(")
            || trimmed.contains("parse_node(")
            || trimmed.contains("parse_packet(")
            || trimmed.contains("parse_element(")
            || trimmed.contains("parse_nested("))
            && (content_contains("parse_tlv")
                || content_contains("parse_node")
                || content_contains("parse_packet")
                || content_contains("parse_element")
                || content_contains("parse_nested"))
            && (trimmed.contains("return parse_")
                || trimmed.contains("= parse_")
                || trimmed.contains("child = parse_"))
            && !content_contains("depth >")
            && !content_contains("depth >=")
            && !content_contains("MAX_DEPTH")
            && !content_contains("max_recursion")
            && !content_contains("MAX_RECURSION")
        {
            violations.push(LinterViolation {
                file_path: file_path.to_string(),
                line_number: line_no,
                rule_id: "CVE-CPP-NET-UNBOUNDED-RECURSION-TLV-PARSER".to_string(),
                cve_id: "CWE-674 / UNBOUNDED-RECURSIVE-NET-PARSER".to_string(),
                severity: "HIGH".to_string(),
                message: "Unbounded recursive protocol parser without depth counter: deeply nested packet structures exhaust thread stack and cause non-recoverable SIGSEGV denial of service".to_string(),
                transmitted_data: Some("recursive_nested_payload".to_string()),
                transmitted_type: Some("stack_frame (Unbounded Recursion Stack Exhaustion)".to_string()),
                remediation: "Pass a recursion depth counter (size_t depth = 0) and enforce if (depth > MAX_RECURSION_DEPTH) throw std::runtime_error(\"nesting limit exceeded\");".to_string(),
            });
        }
    }
}
