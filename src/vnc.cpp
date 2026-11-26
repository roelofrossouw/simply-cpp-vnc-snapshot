#include <sc/vnc-snapshot/vnc.h>

#include <zlib.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <utility>

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace sc::vnc {
    // --- DES ------------------------------------------------------------------------------------------------------
    // FIPS 46-3, encryption only. VNC authentication needs nothing else, and OpenSSL 3 only has DES
    // in its legacy provider (or the deprecated DES_* calls), so it's here rather than a dependency.
    namespace {
        constexpr std::uint8_t pc1[] = {57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
                                        35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
                                        46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};
        constexpr std::uint8_t pc2[] = {14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
                                        26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
                                        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
        constexpr std::uint8_t shifts[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
        constexpr std::uint8_t ip[] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22,
                                       14, 6,  64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35,
                                       27, 19, 11, 3,  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
        constexpr std::uint8_t fp[] = {40, 8,  48, 16, 56, 24, 64, 32, 39, 7,  47, 15, 55, 23, 63, 31, 38, 6,  46, 14, 54, 22,
                                       62, 30, 37, 5,  45, 13, 53, 21, 61, 29, 36, 4,  44, 12, 52, 20, 60, 28, 35, 3,  43, 11,
                                       51, 19, 59, 27, 34, 2,  42, 10, 50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25};
        constexpr std::uint8_t expansion[] = {32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
                                              12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
                                              22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
        constexpr std::uint8_t p[] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
                                      2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25};
        constexpr std::uint8_t s_boxes[8][64] = {
            {14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7, 0, 15, 7,  4,  14, 2,  13, 1,  10, 6, 12, 11, 9,  5,  3,  8,
             4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0, 15, 12, 8, 2,  4,  9,  1,  7,  5,  11, 3, 14, 10, 0,  6,  13},
            {15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10, 3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9,  11, 5,
             0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15, 13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5,  14, 9},
            {10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,  13, 7, 0, 9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
             13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,  1,  10, 13, 0,  6, 9, 8,  7,  4,  15, 14, 3,  11, 5,  2,  12},
            {7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8,  5,  11, 12, 4,  15, 13, 8,  11, 5,  6,  15, 0,  3,  4,  7, 2,  12, 1,  10, 14, 9,
             10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3,  14, 5,  2,  8,  4,  3,  15, 0,  6,  10, 1,  13, 8,  9,  4, 5,  11, 12, 7,  2,  14},
            {2,  12, 4,  1,  7,  10, 11, 6, 8,  5,  3,  15, 13, 0, 14, 9,  14, 11, 2,  12, 4, 7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
             4,  2,  1,  11, 10, 13, 7,  8, 15, 9,  12, 5,  6,  3, 0,  14, 11, 8,  12, 7,  1, 14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3},
            {12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11, 10, 15, 4,  2,  7, 12, 9, 5,  6,  1,  13, 14, 0,  11, 3,  8,
             9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,  4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13},
            {4, 11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1,  13, 0,  11, 7, 4,  9,  1,  10, 14, 3, 5,  12, 2,  15, 8, 6,
             1, 4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2,  6,  11, 13, 8, 1,  4,  10, 7,  9,  5, 0,  15, 14, 2,  3, 12},
            {13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7, 1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9, 2,
             7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8, 2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6, 11}};

        // The table's bits of value (bit 1 the leftmost of width bits), in the table's order.
        template<std::size_t n>
        std::uint64_t permute(const std::uint64_t value, const std::uint8_t (&table)[n], const int width) {
            std::uint64_t out = 0;
            for (const auto bit: table) out = out << 1 | (value >> (width - bit) & 1);
            return out;
        }

        std::uint32_t rotate28(const std::uint32_t half, const int by) { return (half << by | half >> (28 - by)) & 0xFFFFFFF; }
    } // namespace

    std::uint64_t des_encrypt(const std::uint64_t key, const std::uint64_t block) {
        const auto k = permute(key, pc1, 64);
        auto c = static_cast<std::uint32_t>(k >> 28), d = static_cast<std::uint32_t>(k & 0xFFFFFFF);
        std::uint64_t subkeys[16];
        for (int round = 0; round < 16; ++round) {
            c = rotate28(c, shifts[round]);
            d = rotate28(d, shifts[round]);
            subkeys[round] = permute(static_cast<std::uint64_t>(c) << 28 | d, pc2, 56);
        }
        const auto v = permute(block, ip, 64);
        auto l = static_cast<std::uint32_t>(v >> 32), r = static_cast<std::uint32_t>(v);
        for (const auto subkey: subkeys) {
            const auto x = permute(r, expansion, 32) ^ subkey;
            std::uint32_t substituted = 0;
            for (int box = 0; box < 8; ++box) {
                const auto six = static_cast<unsigned>(x >> (42 - 6 * box) & 0x3F);
                const auto row = (six & 0x20) >> 4 | (six & 1), column = six >> 1 & 0xF;
                substituted = substituted << 4 | s_boxes[box][row * 16 + column];
            }
            const auto f = static_cast<std::uint32_t>(permute(substituted, p, 32));
            const auto next = l ^ f;
            l = r;
            r = next;
        }
        return permute(static_cast<std::uint64_t>(r) << 32 | l, fp, 64);
    }

    std::array<std::uint8_t, 16> auth_response(const std::string_view password, const std::array<std::uint8_t, 16> &challenge) {
        std::uint64_t key = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            auto byte = static_cast<std::uint8_t>(i < password.size() ? password[i] : 0);
            std::uint8_t reversed = 0;
            for (int bit = 0; bit < 8; ++bit) reversed = static_cast<std::uint8_t>(reversed << 1 | (byte >> bit & 1));
            key = key << 8 | reversed;
        }
        std::array<std::uint8_t, 16> out{};
        for (std::size_t half = 0; half < 2; ++half) {
            std::uint64_t block = 0;
            for (std::size_t i = 0; i < 8; ++i) block = block << 8 | challenge[half * 8 + i];
            const auto encrypted = des_encrypt(key, block);
            for (std::size_t i = 0; i < 8; ++i) out[half * 8 + i] = static_cast<std::uint8_t>(encrypted >> (56 - 8 * i));
        }
        key = 0;
        return out;
    }

    // --- picture --------------------------------------------------------------------------------------------------
    picture::picture(const sc::size_i size)
        : size_(size), rgb_(static_cast<std::size_t>(size.width()) * static_cast<std::size_t>(size.height()) * 3) {
    }

    std::array<std::uint8_t, 3> picture::pixel(const sc::point_i at) const {
        if (at.x() < 0 || at.y() < 0 || at.x() >= size_.width() || at.y() >= size_.height())
            throw std::out_of_range("sc::vnc::picture: pixel off the picture");
        const auto o = (static_cast<std::size_t>(at.y()) * static_cast<std::size_t>(size_.width()) + static_cast<std::size_t>(at.x())) * 3;
        return {rgb_[o], rgb_[o + 1], rgb_[o + 2]};
    }

    namespace {
        void big_endian(std::string &out, const std::uint32_t value) {
            for (int shift = 24; shift >= 0; shift -= 8) out += static_cast<char>(value >> shift & 0xFF);
        }

        void chunk(std::string &png, const char *type, const std::string &data) {
            big_endian(png, static_cast<std::uint32_t>(data.size()));
            const auto typed = std::string{type, 4} + data;
            png += typed;
            big_endian(png, static_cast<std::uint32_t>(crc32(0, reinterpret_cast<const Bytef *>(typed.data()), static_cast<uInt>(typed.size()))));
        }
    } // namespace

    std::string picture::png() const {
        const auto width = static_cast<std::size_t>(size_.width()), height = static_cast<std::size_t>(size_.height());
        if (width == 0 || height == 0) throw std::invalid_argument("sc::vnc::picture: an empty picture has no PNG");
        std::string raw;
        raw.reserve((width * 3 + 1) * height);
        for (std::size_t y = 0; y < height; ++y) {
            raw += '\0'; // filter: none
            raw.append(reinterpret_cast<const char *>(rgb_.data() + y * width * 3), width * 3);
        }
        auto packed_size = compressBound(static_cast<uLong>(raw.size()));
        std::string packed(packed_size, '\0');
        if (compress2(reinterpret_cast<Bytef *>(packed.data()), &packed_size, reinterpret_cast<const Bytef *>(raw.data()),
                      static_cast<uLong>(raw.size()), 6) != Z_OK)
            throw std::runtime_error("sc::vnc::picture: zlib couldn't compress the picture");
        packed.resize(packed_size);

        std::string header;
        big_endian(header, static_cast<std::uint32_t>(width));
        big_endian(header, static_cast<std::uint32_t>(height));
        header += std::string{"\x08\x02\x00\x00\x00", 5}; // 8 bits, RGB, deflate, adaptive filtering, no interlace
        std::string out{"\x89PNG\r\n\x1a\n", 8};
        chunk(out, "IHDR", header);
        chunk(out, "IDAT", packed);
        chunk(out, "IEND", {});
        return out;
    }

    void picture::save_png(const std::filesystem::path &file) const {
        const auto bytes = png();
        std::ofstream out{file, std::ios::binary | std::ios::trunc};
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        out.close();
        if (!out) throw std::runtime_error("sc::vnc::picture: can't write " + file.string());
    }

    // --- client ---------------------------------------------------------------------------------------------------
    struct client::state {
        int socket = -1;
        std::string server; // host:port, for messages
        vnc::options options;
        int minor = 0;
        vnc::security security = security::none;
        sc::size_i size{};
        std::string name;

        ~state() { close(); }

        void close() {
            if (socket >= 0) ::close(socket);
            socket = -1;
        }

        void forget_password() {
            if (options.password) std::fill(options.password->begin(), options.password->end(), '\0');
            options.password.reset();
        }

        void connect(const std::string &host, const std::uint16_t port) {
            addrinfo hints{};
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            addrinfo *found = nullptr;
            if (const int failed = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &found); failed != 0)
                throw connect_error("can't find " + host + ": " + gai_strerror(failed));
            std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses{found, freeaddrinfo};
            std::string why = "no address";
            for (const auto *at = found; at; at = at->ai_next) {
                const int s = ::socket(at->ai_family, at->ai_socktype, at->ai_protocol);
                if (s < 0) {
                    why = std::strerror(errno);
                    continue;
                }
#ifdef SO_NOSIGPIPE
                const int on = 1;
                setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#endif
                const int flags = fcntl(s, F_GETFL, 0);
                fcntl(s, F_SETFL, flags | O_NONBLOCK);
                int result = ::connect(s, at->ai_addr, at->ai_addrlen);
                if (result != 0 && errno == EINPROGRESS) {
                    pollfd waiting{s, POLLOUT, 0};
                    result = poll(&waiting, 1, static_cast<int>(options.connect_timeout.count()));
                    if (result == 0) {
                        ::close(s);
                        why = "timed out after " + std::to_string(options.connect_timeout.count() / 1000.0).substr(0, 4) + " s";
                        continue;
                    }
                    int error = 0;
                    socklen_t length = sizeof error;
                    if (result > 0) getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &length);
                    else error = errno;
                    result = error == 0 ? 0 : -1;
                    errno = error;
                }
                if (result != 0) {
                    why = errno == ECONNREFUSED ? "connection refused" : std::strerror(errno);
                    ::close(s);
                    continue;
                }
                fcntl(s, F_SETFL, flags);
                socket = s;
                return;
            }
            throw connect_error("can't connect to " + server + ": " + why);
        }

        void read(void *into, std::size_t n) {
            auto *to = static_cast<char *>(into);
            while (n > 0) {
                pollfd waiting{socket, POLLIN, 0};
                const int ready = poll(&waiting, 1, static_cast<int>(options.read_timeout.count()));
                if (ready == 0) throw protocol_error(server + " sent nothing for " + std::to_string(options.read_timeout.count() / 1000) + " s");
                if (ready < 0) {
                    if (errno == EINTR) continue;
                    throw protocol_error("reading from " + server + ": " + std::strerror(errno));
                }
                const auto got = ::recv(socket, to, n, 0);
                if (got == 0) throw protocol_error(server + " closed the connection");
                if (got < 0) {
                    if (errno == EINTR || errno == EAGAIN) continue;
                    throw protocol_error("reading from " + server + ": " + std::strerror(errno));
                }
                to += got;
                n -= static_cast<std::size_t>(got);
            }
        }

        std::uint8_t u8() {
            std::uint8_t v;
            read(&v, 1);
            return v;
        }
        std::uint16_t u16() {
            std::uint8_t b[2];
            read(b, 2);
            return static_cast<std::uint16_t>(b[0] << 8 | b[1]);
        }
        std::uint32_t u32() {
            std::uint8_t b[4];
            read(b, 4);
            return static_cast<std::uint32_t>(b[0]) << 24 | static_cast<std::uint32_t>(b[1]) << 16 | static_cast<std::uint32_t>(b[2]) << 8 | b[3];
        }
        void skip(std::size_t n) {
            char buffer[4096];
            while (n > 0) {
                const auto part = std::min(n, sizeof buffer);
                read(buffer, part);
                n -= part;
            }
        }
        // A length-prefixed string (a reason, the desktop name), up to limit bytes kept.
        std::string text(const std::size_t limit = 4096) {
            const auto length = u32();
            std::string out(std::min<std::size_t>(length, limit), '\0');
            read(out.data(), out.size());
            skip(length - out.size());
            return out;
        }

        void write(const void *bytes, std::size_t n) {
            const auto *from = static_cast<const char *>(bytes);
            while (n > 0) {
#ifdef MSG_NOSIGNAL
                const auto sent = ::send(socket, from, n, MSG_NOSIGNAL);
#else
                const auto sent = ::send(socket, from, n, 0);
#endif
                if (sent < 0) {
                    if (errno == EINTR) continue;
                    throw protocol_error("writing to " + server + ": " + std::strerror(errno));
                }
                from += sent;
                n -= static_cast<std::size_t>(sent);
            }
        }
        void write(std::initializer_list<std::uint8_t> bytes) { write(std::data(bytes), bytes.size()); }

        void handshake() {
            char version[12];
            read(version, sizeof version);
            if (std::memcmp(version, "RFB ", 4) != 0 || version[7] != '.' || version[11] != '\n')
                throw protocol_error(server + " isn't a VNC server (no RFB version)");
            const int major = std::atoi(std::string{version + 4, 3}.c_str()), offered = std::atoi(std::string{version + 8, 3}.c_str());
            if (major < 3) throw protocol_error(server + " speaks RFB " + std::string{version, 11} + ", older than 3.3");
            minor = major > 3 || offered >= 8 ? 8 : offered == 7 ? 7 : 3;
            const auto answer = "RFB 003.00" + std::to_string(minor) + "\n";
            write(answer.data(), answer.size());

            std::vector<std::uint8_t> types;
            if (minor == 3) {
                const auto type = u32();
                if (type == 0) throw auth_error(server + " refused the session: " + text());
                types.push_back(static_cast<std::uint8_t>(type));
            } else {
                const auto count = u8();
                if (count == 0) throw auth_error(server + " refused the session: " + text());
                types.resize(count);
                read(types.data(), count);
            }

            if (std::ranges::find(types, static_cast<std::uint8_t>(security::none)) != types.end()) {
                security = security::none;
                if (minor != 3) write({1});
                if (minor == 8) check_result();
            } else if (std::ranges::find(types, static_cast<std::uint8_t>(security::vnc_authentication)) != types.end()) {
                security = security::vnc_authentication;
                if (!options.password) throw auth_error(server + " wants a VNC password, and none was given");
                if (minor != 3) write({2});
                std::array<std::uint8_t, 16> challenge{};
                read(challenge.data(), challenge.size());
                auto response = auth_response(*options.password, challenge);
                forget_password();
                write(response.data(), response.size());
                response.fill(0);
                check_result();
            } else {
                std::string offered_types;
                for (const auto type: types) offered_types += (offered_types.empty() ? "" : ", ") + std::to_string(type);
                throw auth_error(server + " offers only security types this client doesn't have (" + offered_types +
                                 "; it has 1, none, and 2, VNC authentication)");
            }
            forget_password();

            write({static_cast<std::uint8_t>(options.shared ? 1 : 0)}); // ClientInit
            const auto width = u16(), height = u16();
            size = {static_cast<int>(width), static_cast<int>(height)};
            skip(16); // the server's pixel format: ours is set below
            name = text();

            // SetPixelFormat: 32 bits a pixel, depth 24, little-endian, true colour, 255 each, red at
            // bit 16, green 8, blue 0: each pixel arrives as blue, green, red, unused.
            write({0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0});
            // SetEncodings: Raw only.
            write({2, 0, 0, 1, 0, 0, 0, 0});
        }

        void check_result() {
            const auto result = u32();
            if (result == 0) return;
            std::string why = minor == 8 ? text() : std::string{};
            if (why.empty()) why = result == 2 ? "too many attempts" : "authentication failed";
            if (security == security::vnc_authentication)
                throw auth_error(server + " didn't accept the VNC password (" + why + ")");
            throw auth_error(server + " refused the session: " + why);
        }

        picture snapshot() {
            if (socket < 0) throw error("sc::vnc::client: the connection is closed");
            const auto width = size.width(), height = size.height();
            if (width == 0 || height == 0) throw protocol_error(server + " has an empty screen");
            // FramebufferUpdateRequest, not incremental, for the whole screen.
            write({3, 0, 0, 0, 0, 0, static_cast<std::uint8_t>(width >> 8), static_cast<std::uint8_t>(width),
                   static_cast<std::uint8_t>(height >> 8), static_cast<std::uint8_t>(height)});

            picture out{size};
            auto &rgb = out.rgb();
            std::vector<std::uint8_t> covered(static_cast<std::size_t>(width) * static_cast<std::size_t>(height), 0);
            std::size_t left = covered.size();
            std::vector<std::uint8_t> row;
            while (left > 0) {
                switch (const auto type = u8()) {
                case 0: { // FramebufferUpdate
                    skip(1);
                    const auto rectangles = u16();
                    for (std::uint16_t i = 0; i < rectangles; ++i) {
                        const int x = u16(), y = u16(), w = u16(), h = u16();
                        const auto encoding = static_cast<std::int32_t>(u32());
                        if (encoding == -223) continue; // DesktopSize: ignored, the update still covers the old size
                        if (encoding != 0)
                            throw protocol_error(server + " sent encoding " + std::to_string(encoding) +
                                                 ", which this client doesn't support (it asks for Raw only)");
                        if (x + w > width || y + h > height)
                            throw protocol_error(server + " sent a rectangle off the screen");
                        row.resize(static_cast<std::size_t>(w) * 4);
                        for (int line = 0; line < h; ++line) {
                            read(row.data(), row.size());
                            const auto start = static_cast<std::size_t>(y + line) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x);
                            for (int column = 0; column < w; ++column) {
                                const auto *pixel = &row[static_cast<std::size_t>(column) * 4];
                                auto *to = &rgb[(start + static_cast<std::size_t>(column)) * 3];
                                to[0] = pixel[2];
                                to[1] = pixel[1];
                                to[2] = pixel[0];
                                if (!covered[start + static_cast<std::size_t>(column)]) {
                                    covered[start + static_cast<std::size_t>(column)] = 1;
                                    --left;
                                }
                            }
                        }
                    }
                    break;
                }
                case 1: { // SetColourMapEntries: not used in true colour
                    skip(3);
                    skip(static_cast<std::size_t>(u16()) * 6);
                    break;
                }
                case 2: // Bell
                    break;
                case 3: // ServerCutText
                    skip(3);
                    skip(u32());
                    break;
                default:
                    throw protocol_error(server + " sent message type " + std::to_string(type) + ", which this client doesn't know");
                }
            }
            return out;
        }
    };

    client::client(const std::string &host, const std::uint16_t port, vnc::options options) : state_(std::make_unique<state>()) {
        state_->server = (host.find(':') != std::string::npos ? "[" + host + "]" : host) + ":" + std::to_string(port);
        state_->options = std::move(options);
        try {
            state_->connect(host, port);
            state_->handshake();
        } catch (...) {
            state_->forget_password();
            state_->close();
            throw;
        }
    }

    client::~client() = default;
    client::client(client &&) noexcept = default;
    client &client::operator=(client &&) noexcept = default;

    int client::protocol_minor() const { return state_->minor; }
    vnc::security client::security() const { return state_->security; }
    sc::size_i client::screen_size() const { return state_->size; }
    const std::string &client::desktop_name() const { return state_->name; }
    picture client::snapshot() { return state_->snapshot(); }
    void client::close() {
        if (state_) state_->close();
    }

    picture snapshot(const std::string &host, const std::uint16_t port, const vnc::options &options) {
        client vnc{host, port, options};
        return vnc.snapshot();
    }
} // namespace sc::vnc
