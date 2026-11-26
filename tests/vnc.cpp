// sc::vnc against a tiny RFB server in the same process: DES and VNC authentication's known answers,
// signing in with and without a password (RFB 3.8, 3.7, 3.3), a wrong password, a refused session,
// the screen in several Raw rectangles with other messages in between, the PNG, an encoding it
// didn't ask for, a refused connection and a silent server.
#include <sc/vnc-snapshot/vnc.h>
#include <sc_test.h>

#include <zlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace {
    using bytes = std::vector<std::uint8_t>;

    void put(const int s, const bytes &b) {
        std::size_t done = 0;
        while (done < b.size()) {
            const auto sent = ::send(s, b.data() + done, b.size() - done, 0);
            if (sent <= 0) return;
            done += static_cast<std::size_t>(sent);
        }
    }
    void put(const int s, const std::string &text) { put(s, bytes(text.begin(), text.end())); }
    bytes take(const int s, const std::size_t n) {
        bytes out(n);
        std::size_t done = 0;
        while (done < n) {
            const auto got = ::recv(s, out.data() + done, n - done, 0);
            if (got <= 0) return {};
            done += static_cast<std::size_t>(got);
        }
        return out;
    }
    bytes u16(const unsigned v) { return {static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)}; }
    bytes u32(const std::uint32_t v) {
        return {static_cast<std::uint8_t>(v >> 24), static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)};
    }
    bytes cat(std::initializer_list<bytes> parts) {
        bytes out;
        for (const auto &p: parts) out.insert(out.end(), p.begin(), p.end());
        return out;
    }
    bytes text(const std::string &t) { return cat({u32(static_cast<std::uint32_t>(t.size())), bytes(t.begin(), t.end())}); }
    bytes rect(const unsigned x, const unsigned y, const unsigned w, const unsigned h, const std::int32_t encoding) {
        return cat({u16(x), u16(y), u16(w), u16(h), u32(static_cast<std::uint32_t>(encoding))});
    }

    // One connection on 127.0.0.1, served by script on a thread.
    class fake_server {
    public:
        explicit fake_server(std::function<void(int)> script) {
            listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            ::bind(listener_, reinterpret_cast<sockaddr *>(&address), sizeof address);
            ::listen(listener_, 1);
            socklen_t length = sizeof address;
            getsockname(listener_, reinterpret_cast<sockaddr *>(&address), &length);
            port_ = ntohs(address.sin_port);
            thread_ = std::thread{[this, script = std::move(script)] {
                const int s = ::accept(listener_, nullptr, nullptr);
                if (s < 0) return;
                script(s);
                ::close(s);
            }};
        }
        ~fake_server() {
            ::shutdown(listener_, SHUT_RDWR);
            ::close(listener_);
            if (thread_.joinable()) thread_.join();
        }
        [[nodiscard]] std::uint16_t port() const { return port_; }

    private:
        int listener_ = -1;
        std::uint16_t port_ = 0;
        std::thread thread_;
    };

    const bytes challenge = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    // VNC authentication's answer for "secret" to that challenge (from the Python reference).
    const bytes secret_answer = {0xee, 0x22, 0x53, 0x9f, 0x33, 0xa5, 0x98, 0x3e, 0xc1, 0x2f, 0x9c, 0x2e, 0xdb, 0xc9, 0x95, 0xdd};

    // The test screen's colour at (x, y): red x*60, green y*80, blue 7.
    bytes pixel_bgrx(const unsigned x, const unsigned y) { return {7, static_cast<std::uint8_t>(y * 80), static_cast<std::uint8_t>(x * 60), 0}; }
    bytes pixels(const unsigned x0, const unsigned y0, const unsigned w, const unsigned h) {
        bytes out;
        for (unsigned y = y0; y < y0 + h; ++y)
            for (unsigned x = x0; x < x0 + w; ++x) {
                const auto p = pixel_bgrx(x, y);
                out.insert(out.end(), p.begin(), p.end());
            }
        return out;
    }

    // After signing in: ClientInit, ServerInit (a 4x3 screen), the client's pixel format, encodings
    // and update request; shared is what ClientInit said.
    bool serve_init(const int s, bool &shared, bool &asked_right) {
        const auto init = take(s, 1);
        if (init.empty()) return false;
        shared = init[0] == 1;
        put(s, cat({u16(4), u16(3), bytes(16, 0), text("test desktop")}));
        const auto format = take(s, 20), encodings = take(s, 8), request = take(s, 10);
        asked_right = format == bytes{0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0} &&
                      encodings == bytes{2, 0, 0, 1, 0, 0, 0, 0} && request == bytes{3, 0, 0, 0, 0, 0, 0, 4, 0, 3};
        return true;
    }

    // The 4x3 screen: a bell, cut text, then two updates: the top two rows with a DesktopSize
    // rectangle, then the last row in two pieces, one overlapping what came before.
    void serve_screen(const int s) {
        put(s, bytes{2});
        put(s, cat({bytes{3, 0, 0, 0}, text("clipboard")}));
        put(s, cat({bytes{0, 0}, u16(2), rect(0, 0, 4, 3, -223), rect(0, 0, 4, 2, 0), pixels(0, 0, 4, 2)}));
        put(s, cat({bytes{0, 0}, u16(2), rect(0, 1, 2, 2, 0), pixels(0, 1, 2, 2), rect(2, 2, 2, 1, 0), pixels(2, 2, 2, 1)}));
    }

    std::uint32_t big_endian(const std::string &b, const std::size_t at) {
        std::uint32_t v = 0;
        for (std::size_t i = 0; i < 4; ++i) v = v << 8 | static_cast<unsigned char>(b[at + i]);
        return v;
    }
} // namespace

int main() {
    SECTION("DES and VNC authentication");
    CHECK_EQ(sc::vnc::des_encrypt(0x133457799BBCDFF1ULL, 0x0123456789ABCDEFULL), 0x85E813540F0AB405ULL);
    std::array<std::uint8_t, 16> ch{};
    std::copy(challenge.begin(), challenge.end(), ch.begin());
    const auto answer = sc::vnc::auth_response("secret", ch);
    CHECK(bytes(answer.begin(), answer.end()) == secret_answer);
    const bytes long_answer = {0x76, 0x54, 0x38, 0x20, 0xb2, 0xc3, 0x58, 0xfe, 0x35, 0x90, 0x83, 0xc1, 0x92, 0xfa, 0x77, 0xc9};
    const auto cut = sc::vnc::auth_response("longerthan8", ch);
    CHECK(bytes(cut.begin(), cut.end()) == long_answer);
    const auto same = sc::vnc::auth_response("longerth", ch);
    CHECK(bytes(same.begin(), same.end()) == long_answer); // only 8 bytes count

    SECTION("RFB 3.8, VNC authentication, the screen in Raw rectangles");
    {
        bool answered = false, shared = false, asked_right = false;
        fake_server server{[&](const int s) {
            put(s, std::string{"RFB 003.008\n"});
            if (take(s, 12) != bytes{'R', 'F', 'B', ' ', '0', '0', '3', '.', '0', '0', '8', '\n'}) return;
            put(s, bytes{1, 2});
            if (take(s, 1) != bytes{2}) return;
            put(s, challenge);
            answered = take(s, 16) == secret_answer;
            put(s, u32(answered ? 0 : 1));
            if (!answered || !serve_init(s, shared, asked_right)) return;
            serve_screen(s);
            take(s, 1); // until the client closes
        }};
        sc::vnc::client vnc{"127.0.0.1", server.port(), {.password = "secret"}};
        CHECK_EQ(vnc.protocol_minor(), 8);
        CHECK(vnc.security() == sc::vnc::security::vnc_authentication);
        CHECK_EQ(vnc.screen_size(), (sc::size_i{4, 3}));
        CHECK_EQ(vnc.desktop_name(), std::string{"test desktop"});
        const auto screen = vnc.snapshot();
        vnc.close();
        CHECK(answered);
        CHECK(shared);
        CHECK(asked_right);
        CHECK_EQ(screen.size(), (sc::size_i{4, 3}));
        bool all = true;
        for (int y = 0; y < 3; ++y)
            for (int x = 0; x < 4; ++x) {
                const auto p = screen.pixel({x, y});
                all = all && p[0] == x * 60 && p[1] == y * 80 && p[2] == 7;
            }
        CHECK(all);
        CHECK_THROWS_AS(static_cast<void>(screen.pixel({4, 0})), std::out_of_range);

        SECTION("the PNG");
        const auto png = screen.png();
        CHECK(png.starts_with(std::string{"\x89PNG\r\n\x1a\n", 8}));
        CHECK_EQ(png.substr(12, 4), std::string{"IHDR"});
        CHECK_EQ(big_endian(png, 16), 4u);
        CHECK_EQ(big_endian(png, 20), 3u);
        CHECK_EQ(static_cast<int>(png[24]), 8);
        CHECK_EQ(static_cast<int>(png[25]), 2);
        std::string packed;
        for (std::size_t at = 8; at + 8 <= png.size();) {
            const auto length = big_endian(png, at);
            const auto crc = crc32(0, reinterpret_cast<const Bytef *>(png.data() + at + 4), length + 4);
            CHECK_EQ(big_endian(png, at + 8 + length), static_cast<std::uint32_t>(crc));
            if (png.compare(at + 4, 4, "IDAT") == 0) packed += png.substr(at + 8, length);
            at += 12 + length;
        }
        std::string raw(3 * (1 + 4 * 3), '\0');
        auto raw_size = static_cast<uLongf>(raw.size());
        CHECK_EQ(uncompress(reinterpret_cast<Bytef *>(raw.data()), &raw_size, reinterpret_cast<const Bytef *>(packed.data()),
                            static_cast<uLong>(packed.size())), Z_OK);
        CHECK_EQ(static_cast<std::size_t>(raw_size), raw.size());
        CHECK_EQ(static_cast<int>(static_cast<unsigned char>(raw[1 + 13 + 3 * 3])), 180); // (3, 1)'s red
        CHECK_EQ(static_cast<int>(static_cast<unsigned char>(raw[2 * 13 + 1 + 1])), 160); // (0, 2)'s green
    }

    SECTION("a wrong password");
    {
        fake_server server{[](const int s) {
            put(s, std::string{"RFB 003.008\n"});
            take(s, 12);
            put(s, bytes{1, 2});
            take(s, 1);
            put(s, challenge);
            take(s, 16);
            put(s, cat({u32(1), text("Authentication failure")}));
        }};
        try {
            sc::vnc::client vnc{"127.0.0.1", server.port(), {.password = "wrong"}};
            CHECK_MSG(false, "no auth_error");
        } catch (const sc::vnc::auth_error &e) {
            const std::string what = e.what();
            CHECK(what.find("Authentication failure") != std::string::npos);
            CHECK(what.find("wrong") == std::string::npos); // never the password
        }
    }

    SECTION("a password wanted but not given");
    {
        fake_server server{[](const int s) {
            put(s, std::string{"RFB 003.008\n"});
            take(s, 12);
            put(s, bytes{1, 2});
            take(s, 1);
        }};
        CHECK_THROWS_AS((sc::vnc::client{"127.0.0.1", server.port()}), sc::vnc::auth_error);
    }

    SECTION("RFB 3.7: the session refused");
    {
        fake_server server{[](const int s) {
            put(s, std::string{"RFB 003.007\n"});
            take(s, 12);
            put(s, cat({bytes{0}, text("Too many connections")}));
        }};
        try {
            sc::vnc::client vnc{"127.0.0.1", server.port()};
            CHECK_MSG(false, "no auth_error");
        } catch (const sc::vnc::auth_error &e) {
            CHECK(std::string{e.what()}.find("Too many connections") != std::string::npos);
        }
    }

    SECTION("RFB 3.3, no security, the screen");
    {
        bool shared = true, asked_right = false;
        fake_server server{[&](const int s) {
            put(s, std::string{"RFB 003.003\n"});
            if (take(s, 12).empty()) return;
            put(s, u32(1));
            if (!serve_init(s, shared, asked_right)) return;
            serve_screen(s);
            take(s, 1);
        }};
        sc::vnc::client vnc{"127.0.0.1", server.port(), {.shared = false}};
        CHECK_EQ(vnc.protocol_minor(), 3);
        CHECK(vnc.security() == sc::vnc::security::none);
        const auto screen = vnc.snapshot();
        vnc.close();
        CHECK(!shared);
        CHECK(asked_right);
        CHECK(screen.pixel({3, 2}) == (std::array<std::uint8_t, 3>{180, 160, 7}));
    }

    SECTION("an encoding it didn't ask for");
    {
        fake_server server{[](const int s) {
            put(s, std::string{"RFB 003.008\n"});
            take(s, 12);
            put(s, bytes{1, 1});
            take(s, 1);
            put(s, u32(0));
            bool shared, asked_right;
            if (!serve_init(s, shared, asked_right)) return;
            put(s, cat({bytes{0, 0}, u16(1), rect(0, 0, 4, 3, 16), bytes(64, 0)}));
            take(s, 1);
        }};
        sc::vnc::client vnc{"127.0.0.1", server.port()};
        try {
            static_cast<void>(vnc.snapshot());
            CHECK_MSG(false, "no protocol_error");
        } catch (const sc::vnc::protocol_error &e) {
            CHECK(std::string{e.what()}.find("encoding 16") != std::string::npos);
        }
    }

    SECTION("not a VNC server, a silent one, a refused connection");
    {
        fake_server http{[](const int s) {
            put(s, std::string{"HTTP/1.1 400 Bad Request\r\n\r\n"});
            take(s, 1);
        }};
        CHECK_THROWS_AS((sc::vnc::client{"127.0.0.1", http.port()}), sc::vnc::protocol_error);

        fake_server silent{[](const int s) { take(s, 1); }};
        CHECK_THROWS_AS((sc::vnc::client{"127.0.0.1", silent.port(), {.read_timeout = std::chrono::milliseconds{200}}}), sc::vnc::protocol_error);

        std::uint16_t closed_port;
        {
            const int s = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            ::bind(s, reinterpret_cast<sockaddr *>(&address), sizeof address);
            socklen_t length = sizeof address;
            getsockname(s, reinterpret_cast<sockaddr *>(&address), &length);
            closed_port = ntohs(address.sin_port);
            ::close(s);
        }
        try {
            sc::vnc::client vnc{"127.0.0.1", closed_port};
            CHECK_MSG(false, "no connect_error");
        } catch (const sc::vnc::connect_error &e) {
            CHECK(std::string{e.what()}.find("refused") != std::string::npos);
        }
    }

    TEST_SUMMARY();
}
